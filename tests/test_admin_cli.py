from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from signur.admin_cli import main
from signur.config import Settings
from signur.database import Base
from signur.models import AuditEvent, User, UserRole


def _cli_settings(path: Path) -> Settings:
    return Settings(
        environment="test",
        database_url=f"sqlite+pysqlite:///{path}",
        storage_root=path.parent / "blobs",
    )


def test_cli_lists_users_and_can_restore_an_admin(tmp_path, capsys):  # type: ignore[no-untyped-def]
    database = tmp_path / "signur.sqlite"
    settings = _cli_settings(database)
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        session.add(
            User(
                identity_authority="https://auth.test/",
                external_id="locked-out",
                display_name="Utente Bloccato",
                email="locked@example.test",
                role=UserRole.NO_ACCESS,
            )
        )
        session.commit()
    engine.dispose()

    assert main(["users", "list"], settings) == 0
    assert "locked-out" in capsys.readouterr().out
    assert main(["users", "set-role", "locked@example.test", "admin"], settings) == 0

    engine = create_engine(settings.database_url)
    with Session(engine) as session:
        user = session.scalar(select(User).where(User.external_id == "locked-out"))
        event = session.scalar(
            select(AuditEvent).where(AuditEvent.action == "user.role.changed.cli")
        )
        assert user is not None
        assert user.role is UserRole.ADMIN
        assert event is not None
        assert event.actor_user_id is None
        assert event.details["previous_role"] == "no_access"
    engine.dispose()


def test_cli_reports_unknown_user_without_changing_data(tmp_path, capsys):  # type: ignore[no-untyped-def]
    database = tmp_path / "signur.sqlite"
    settings = _cli_settings(database)
    engine = create_engine(settings.database_url)
    Base.metadata.create_all(engine)
    engine.dispose()

    assert main(["users", "set-role", "missing", "admin"], settings) == 1
    assert "Nessun utente" in capsys.readouterr().err


def test_running_it_bare_explains_itself(capsys):  # type: ignore[no-untyped-def]
    """Someone locked out of the interface needs to be told what this can do."""
    code = main([])

    stampato = capsys.readouterr().out
    assert code == 0
    assert "users" in stampato
    assert "set-role" in stampato
    assert "Esempi" in stampato


def test_a_group_without_a_command_shows_that_group(capsys):  # type: ignore[no-untyped-def]
    code = main(["users"])

    stampato = capsys.readouterr().out
    assert code == 2
    assert "list" in stampato and "set-role" in stampato


def test_a_wrong_command_shows_the_ones_that_exist(capsys):  # type: ignore[no-untyped-def]
    code = main(["utenti"])

    catturato = capsys.readouterr()
    assert code == 2
    assert "users" in catturato.out + catturato.err
