import argparse
import getpass
import sys

from periscope.auth.users import create_user
from periscope.db import migrate, session_scope


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="periscope")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap-admin", help="créer le premier administrateur")
    b.add_argument("--username", required=True)
    sub.add_parser("migrate", help="appliquer les migrations de base de données")
    args = p.parse_args(argv)

    if args.cmd == "migrate":
        migrate()
        print("Base de données à jour.")
        return 0

    password = getpass.getpass("Mot de passe (12 caractères minimum) : ")
    if password != getpass.getpass("Confirmation : "):
        print("Erreur : les mots de passe diffèrent.", file=sys.stderr)
        return 1
    migrate()
    try:
        with session_scope() as s:
            create_user(s, args.username, password, "admin")
    except ValueError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 1
    print("Administrateur créé. À la première connexion, enregistrez un second facteur (TOTP).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
