import argparse
import sys
import uuid
from collections.abc import Sequence
from contextlib import suppress
from typing import NoReturn

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from signur.audit import record_event
from signur.config import Settings, get_settings
from signur.database import build_engine
from signur.models import User, UserRole


class CliError(Exception):
    pass


EXAMPLES = """Examples:
  signur-admin users list
  signur-admin users set-role mario@esempio.it admin
  signur-admin users set-role 7a9c37cb-98c6-477c-8cf1-67271c281eba no_access
"""


class _Parser(argparse.ArgumentParser):
    """Show what can be done, instead of only saying what was wrong."""

    def error(self, message: str) -> NoReturn:
        self.print_help()
        print(f"\nError: {message}", file=sys.stderr)
        raise SystemExit(2)


def _parser() -> _Parser:
    parser = _Parser(
        prog="signur-admin",
        description=(
            "Local administration for Signur, to be run on the machine hosting it: "
            "it works straight on the database, without going through the interface. "
            "It is there for when nobody can get in any more, say after the last "
            "administrator was demoted."
        ),
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    users = commands.add_parser(
        "users",
        help="List the accounts and change their role.",
        description="List the accounts and change their role.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    # Each group carries its own parser, so an incomplete command line can show
    # the help of the group that was asked for.
    users.set_defaults(group=users)
    user_commands = users.add_subparsers(dest="users_command")
    user_commands.add_parser("list", help="List the registered accounts.")
    set_role = user_commands.add_parser("set-role", help="Change the role of an account.")
    set_role.add_argument("identifier", help="UUID, username or email address.")
    set_role.add_argument(
        "role",
        choices=[role.value for role in UserRole],
        help="The role to assign.",
    )
    return parser


def _find_user(session: Session, identifier: str) -> User:
    filters = [User.external_id == identifier]
    with suppress(ValueError):
        filters.append(User.id == uuid.UUID(identifier))
    filters.append(func.lower(User.email) == identifier.lower())
    matches = session.scalars(select(User).where(or_(*filters))).unique().all()
    if not matches:
        raise CliError(f"No account matches {identifier!r}.")
    if len(matches) > 1:
        raise CliError("That identifier matches more than one account: use the UUID.")
    return matches[0]


def _list_users(session: Session) -> None:
    users = session.scalars(select(User).order_by(User.first_seen_at, User.id)).all()
    print("ID\tUSERNAME\tEMAIL\tROLE\tNAME")
    for user in users:
        print(
            f"{user.id}\t{user.external_id}\t{user.email or '-'}\t"
            f"{user.role.value}\t{user.display_name}"
        )


def _set_role(session: Session, identifier: str, role: UserRole) -> None:
    user = _find_user(session, identifier)
    previous_role = user.role
    user.role = role
    record_event(
        session,
        actor=None,
        action="user.role.changed.cli",
        entity_type="user",
        entity_id=user.id,
        request_id=f"cli-{uuid.uuid4()}",
        details={
            "previous_role": previous_role.value,
            "new_role": role.value,
            "identifier": identifier,
        },
    )
    session.commit()
    print(f"{user.display_name} ({user.id}): {previous_role.value} -> {role.value}")


def main(argv: Sequence[str] | None = None, settings: Settings | None = None) -> int:
    parser = _parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exit_code:
        # argparse ends the process on --help and on a wrong command line; here the
        # outcome travels as a return value, like every other path in this module.
        return int(exit_code.code or 0)
    if args.command is None:
        # Nothing asked: say what there is, rather than complain about it.
        parser.print_help()
        return 0
    if args.users_command is None:
        args.group.print_help()
        return 2
    engine = build_engine(settings or get_settings())
    try:
        with Session(engine) as session:
            if args.users_command == "list":
                _list_users(session)
            elif args.users_command == "set-role":
                _set_role(session, args.identifier, UserRole(args.role))
    except CliError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    return 0


def run() -> None:
    raise SystemExit(main())
