"""Operational command line: ``python -m app.cli <command>``."""

from __future__ import annotations

import argparse
import sys

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.context import build_context
from app.db.session import get_engine, init_engine
from app.seed import seed_demo, seed_reference
from app.services.audit import verify_chain


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="aic")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("seed-reference", help="Install roles, permissions, example classifications and retention rules")
    demo = sub.add_parser("seed-demo", help="Create synthetic services and users (development only)")
    demo.add_argument("--password", help="Shared demo password (generated if omitted)")
    sub.add_parser("verify-audit", help="Verify the integrity of the audit hash chain")
    boot = sub.add_parser("bootstrap-admin", help="Create the first technical administrator (two operators present)")
    boot.add_argument("--username", required=True)
    boot.add_argument("--professional-id", required=True)
    boot.add_argument("--service-code", required=True)
    boot.add_argument("--service-name", required=True)
    boot.add_argument("--operators", required=True, help="Professional ids of the two operators, comma separated")
    args = parser.parse_args(argv)

    settings = get_settings()
    build_context(settings)
    init_engine(settings.database_url)
    with Session(get_engine()) as db:
        if args.command == "seed-reference":
            seed_reference(db)
            print("Reference data installed.")
        elif args.command == "seed-demo":
            if settings.is_production_like:
                print("Refusing to create demo users outside development.", file=sys.stderr)
                return 2
            seed_reference(db)
            password = seed_demo(db, args.password)
            print("Synthetic users created. Shared development password:", password)
            print("Each user enrols TOTP at first login.")
        elif args.command == "bootstrap-admin":
            return _bootstrap_admin(db, args)
        elif args.command == "verify-audit":
            report = verify_chain(db)
            print(report)
            return 0 if report.valid else 1
    return 0


def _bootstrap_admin(db: Session, args) -> int:
    """Only works while no technical administrator exists; the password is typed, never passed as argument."""
    import getpass

    from sqlalchemy import select

    from app.core.security import hash_password, password_policy_errors, utcnow
    from app.models import Role, Service, User
    from app.services import audit

    operators = [o.strip() for o in args.operators.split(",") if o.strip()]
    if len(set(operators)) < 2:
        print("Two distinct operators are required.", file=sys.stderr)
        return 2
    seed_reference(db)
    admin_role = db.scalar(select(Role).where(Role.code == "tech_admin"))
    if any(admin_role in u.roles for u in db.scalars(select(User))):
        print("A technical administrator already exists; use the administration API.", file=sys.stderr)
        return 2
    password = getpass.getpass("Initial password: ")
    if password != getpass.getpass("Confirm: ") or password_policy_errors(password):
        print("Passwords differ or do not meet the policy.", file=sys.stderr)
        return 2
    service = db.scalar(select(Service).where(Service.code == args.service_code))
    if service is None:
        service = Service(code=args.service_code, name=args.service_name)
        db.add(service)
        db.flush()
    user = User(username=args.username, display_name=args.username, professional_id=args.professional_id,
                service_id=service.id, clearance_rank=0, password_hash=hash_password(password),
                password_changed_at=utcnow(), roles=[admin_role])
    db.add(user)
    db.flush()
    audit.record(db, audit.AuditContext(actor_label=f"cli:{'+'.join(operators)}"), "user.bootstrap_admin",
                 "administration", "success", "user", user.id, {"operators": ",".join(operators)})
    print("Technical administrator created. TOTP enrolment happens at first login.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
