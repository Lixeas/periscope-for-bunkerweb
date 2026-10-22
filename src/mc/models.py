from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import JSON, ForeignKey, LargeBinary, String, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from mc.clock import utcnow
from mc.db import Base


class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(16), default="reader")  # admin | reader
    totp_secret_enc: Mapped[str | None] = mapped_column(String(255), default=None)
    totp_confirmed: Mapped[bool] = mapped_column(default=False)
    totp_last_step: Mapped[int] = mapped_column(default=0)  # anti-rejeu TOTP
    failed_attempts: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime | None] = mapped_column(default=None)
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    credentials: Mapped[list["Credential"]] = relationship(cascade="all, delete-orphan")
    backup_codes: Mapped[list["BackupCode"]] = relationship(cascade="all, delete-orphan")


class Credential(Base):
    """Passkey WebAuthn."""
    __tablename__ = "credentials"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    credential_id: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    public_key: Mapped[bytes] = mapped_column(LargeBinary)
    sign_count: Mapped[int] = mapped_column(default=0)
    name: Mapped[str] = mapped_column(String(64), default="passkey")
    created_at: Mapped[datetime] = mapped_column(default=utcnow)


class BackupCode(Base):
    __tablename__ = "backup_codes"
    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    code_hash: Mapped[str] = mapped_column(String(64))
    used: Mapped[bool] = mapped_column(default=False)


class Session(Base):
    __tablename__ = "sessions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 du jeton cookie
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    csrf: Mapped[str] = mapped_column(String(64))
    mfa_ok: Mapped[bool] = mapped_column(default=False)
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)  # WebAuthn en cours
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


class Instance(Base):
    __tablename__ = "instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    base_url: Mapped[str] = mapped_column(String(255))
    token_enc: Mapped[str] = mapped_column(String(512))
    verify_tls: Mapped[bool] = mapped_column(default=True)
    probe_host: Mapped[str] = mapped_column(String(255), default="")  # vide = hôte de base_url
    tls_port: Mapped[int] = mapped_column(default=443)
    enabled: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # unknown|ok|degraded|down
    last_ok_at: Mapped[datetime | None] = mapped_column(default=None)
    last_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str] = mapped_column(String(1024), default="")
    version: Mapped[str | None] = mapped_column(String(32), default=None)
    latency_ms: Mapped[float | None] = mapped_column(default=None)
    snapshots: Mapped[list["Snapshot"]] = relationship(cascade="all, delete-orphan")
    probes: Mapped[list["CertProbe"]] = relationship(cascade="all, delete-orphan")

    @property
    def probe_target(self) -> str:
        return self.probe_host or urlparse(self.base_url).hostname or ""


class Snapshot(Base):
    """Dernier état connu par (instance, type)."""
    __tablename__ = "snapshots"
    __table_args__ = (UniqueConstraint("instance_id", "kind"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id"))
    kind: Mapped[str] = mapped_column(String(16))  # services|bans|jobs|plugins
    payload: Mapped[list] = mapped_column(JSON)
    collected_at: Mapped[datetime] = mapped_column(default=utcnow)


class CertProbe(Base):
    __tablename__ = "cert_probes"
    __table_args__ = (UniqueConstraint("instance_id", "domain"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id"))
    domain: Mapped[str] = mapped_column(String(255))
    present: Mapped[bool] = mapped_column(default=False)
    issuer: Mapped[str] = mapped_column(String(255), default="")
    not_after: Mapped[datetime | None] = mapped_column(default=None)
    error: Mapped[str] = mapped_column(String(512), default="")
    probed_at: Mapped[datetime] = mapped_column(default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(default=utcnow)
    username: Mapped[str] = mapped_column(String(64), default="")
    event: Mapped[str] = mapped_column(String(64))
    detail: Mapped[str] = mapped_column(String(512), default="")
    ip: Mapped[str] = mapped_column(String(64), default="")
