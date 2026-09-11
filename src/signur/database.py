from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from signur.config import Settings, get_settings


class Base(DeclarativeBase):
    pass


def build_engine(settings: Settings):  # type: ignore[no-untyped-def]
    connect_args = (
        {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
    )
    return create_engine(settings.database_url, pool_pre_ping=True, connect_args=connect_args)


engine = build_engine(get_settings())
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_session() -> Generator[Session]:
    with SessionLocal() as session:
        yield session
