import argparse
import asyncio
import getpass
import logging
import sys
from pathlib import Path

from periscope.auth.users import create_user
from periscope.db import migrate, session_scope


def _agent(args) -> int:
    from periscope.agent import Agent, AgentError, AgentSettings, enroll, healthy

    cfg = AgentSettings()
    directory = Path(args.dir) if args.dir else cfg.dir
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)  # one line per request otherwise
    try:
        if args.agent_cmd == "enroll":
            bundle = args.bundle or sys.stdin.readline()
            name = asyncio.run(enroll(bundle, directory))
            print(f"Agent enrolled for instance {name!r}. Start it with: periscope agent run")
            return 0
        if args.agent_cmd == "health":  # exit code for Docker / Kubernetes probes
            return 0 if healthy(directory) else 1
        cfg.dir = directory
        asyncio.run(Agent(cfg).run_forever())
    except AgentError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="periscope")
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("bootstrap-admin", help="create the first administrator")
    b.add_argument("--username", required=True)
    sub.add_parser("migrate", help="apply the database migrations")
    a = sub.add_parser("agent", help="Periscope agent (runs next to a BunkerWeb instance)")
    asub = a.add_subparsers(dest="agent_cmd", required=True)
    e = asub.add_parser("enroll", help="enroll this agent with the bundle shown by the console")
    e.add_argument("bundle", nargs="?", help="enrollment bundle (read from stdin if omitted)")
    e.add_argument("--dir", help="agent directory (default: PERISCOPE_AGENT_DIR)")
    r = asub.add_parser("run", help="collect the local BunkerWeb instance and report to the console")
    r.add_argument("--dir", help="agent directory (default: PERISCOPE_AGENT_DIR)")
    h = asub.add_parser("health", help="exit 0 if the console accepted a recent report (for probes)")
    h.add_argument("--dir", help="agent directory (default: PERISCOPE_AGENT_DIR)")
    args = p.parse_args(argv)

    if args.cmd == "agent":
        return _agent(args)

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
