import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from sqlalchemy import Engine, create_engine, select
from sqlalchemy.orm import Session

from signur.config import get_settings
from signur.database import Base
from signur.migrate import build_alembic_config
from signur.models import (
    AnalysisStatus,
    BlobState,
    Document,
    DocumentState,
    InputFormat,
    PdfaStatus,
    UserRole,
)


@pytest.fixture
def database_url(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """Point the whole stack at a throwaway file: env.py reads the settings itself."""
    url = f"sqlite+pysqlite:///{tmp_path / 'signur.db'}"
    monkeypatch.setenv("SIGNUR_DATABASE_URL", url)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()


def migrated(url: str, revision: str) -> Engine:
    """Bring the database to the given revision, as a deploy would."""
    command.upgrade(build_alembic_config(get_settings()), revision)
    return create_engine(url)


def insert_document(engine: Engine) -> None:
    """Write the rows an old install would already have, through the schema."""
    tables = Base.metadata.tables
    user_id, blob_id = uuid.uuid4(), uuid.uuid4()
    with engine.begin() as connection:
        connection.execute(
            tables["users"].insert(),
            {
                "id": user_id,
                "identity_authority": "https://auth.test/",
                "external_id": "operator",
                "display_name": "Operator",
                "role": UserRole.USER,
            },
        )
        connection.execute(
            tables["blobs"].insert(),
            {
                "id": blob_id,
                "storage_key": "originals/legacy",
                "kind": "original",
                "sha256": "0" * 64,
                "size_bytes": 9,
                "state": BlobState.STORED,
            },
        )
        connection.execute(
            tables["documents"].insert(),
            {
                "id": uuid.uuid4(),
                "owner_user_id": user_id,
                "uploaded_by_user_id": user_id,
                "original_name": "documento.bin",
                "input_format": InputFormat.OPAQUE,
                "detected_media_type": "application/octet-stream",
                "original_blob_id": blob_id,
                "sha256": "0" * 64,
                "size_bytes": 9,
                "state": DocumentState.TO_SIGN,
                "analysis_status": AnalysisStatus.COMPLETE,
                "capabilities": [],
                "analysis_warnings": [],
                "pdfa_violations": [],
                "pdfa_status": PdfaStatus.NOT_APPLICABLE,
                "version": 1,
            },
        )


def test_enum_defaults_use_the_member_names(database_url: str) -> None:
    engine = migrated(database_url, "head")
    inspector = sa.inspect(engine)
    wrong = []
    for name, table in Base.metadata.tables.items():
        stored = {column["name"]: column for column in inspector.get_columns(name)}
        for column in table.columns:
            if not isinstance(column.type, sa.Enum) or column.type.enum_class is None:
                continue
            default = stored[column.name].get("default")
            if default is None:
                continue
            if default.strip("'\"") not in column.type.enum_class.__members__:
                wrong.append(f"{name}.{column.name} defaults to {default}")
    assert wrong == []


def test_a_pdfa_status_written_as_a_value_is_repaired(database_url: str) -> None:
    engine = migrated(database_url, "20260911_11")
    insert_document(engine)
    with engine.begin() as connection:
        # What the 08 server default wrote into every row that already existed.
        connection.execute(sa.text("UPDATE documents SET pdfa_status = 'not_applicable'"))
    engine.dispose()

    engine = migrated(database_url, "head")
    with Session(engine) as session:
        document = session.scalars(select(Document)).one()
        assert document.pdfa_status is PdfaStatus.NOT_APPLICABLE
