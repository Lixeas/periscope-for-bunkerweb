import argparse
import getpass
import sys

from periscope.auth.users import create_user
from periscope.db import migrate, session_scope


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="periscope")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap-admin", help="create the first administrator")
    b.add_argument("--username", required=True)
    sub.add_parser("migrate", help="apply the database migrations")
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        migrate()
        print("Database is up to date.")
        return 0

    password = getpass.getpass("Password (12 characters minimum): ")
    if password != getpass.getpass("Confirmation: "):
        print("Error: the passwords do not match.", file=sys.stderr)
        return 1
    migrate()
    try:
        with session_scope() as s:
            create_user(s, args.username, password, "admin")
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    print("Administrator created. At first login, enroll a second factor (TOTP).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
