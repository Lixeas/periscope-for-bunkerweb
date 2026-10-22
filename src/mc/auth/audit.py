from sqlalchemy.orm import Session

from mc.models import AuditLog


def audit(db: Session, event: str, username: str = "", detail: str = "", ip: str = "") -> None:
    db.add(AuditLog(event=event, username=username[:64], detail=detail[:512], ip=ip[:64]))
