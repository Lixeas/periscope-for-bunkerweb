from datetime import datetime
from urllib.parse import urlparse

from sqlalchemy import JSON, Column, ForeignKey, LargeBinary, String, Table, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from periscope.clock import utcnow
from periscope.db import Base


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
    lang: Mapped[str | None] = mapped_column(String(5), default=None)  # UI language preference (en | fr)
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
    id: Mapped[str] = mapped_column(String(64), primary_key=True)  # sha256 of the cookie token
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    csrf: Mapped[str] = mapped_column(String(64))
    mfa_ok: Mapped[bool] = mapped_column(default=False)
    challenge: Mapped[bytes | None] = mapped_column(LargeBinary, default=None)  # WebAuthn in progress
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(default=utcnow)


instance_tags = Table(
    "instance_tags", Base.metadata,
    Column("instance_id", ForeignKey("instances.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class Tag(Base):
    """Free label grouping instances (typically one tag per customer)."""
    __tablename__ = "tags"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(32), unique=True)


class Instance(Base):
    __tablename__ = "instances"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    # direct = Periscope polls the BunkerWeb API itself (API user); agent = a Periscope agent next
    # to the instance pushes its reports over mutual TLS (no inbound access to the instance's network).
    connection: Mapped[str] = mapped_column(String(8), default="direct", server_default="direct")
    base_url: Mapped[str] = mapped_column(String(255), default="")  # direct mode only
    api_username: Mapped[str] = mapped_column(String(128), default="", server_default="")
    api_password_enc: Mapped[str] = mapped_column(String(512), default="", server_default="")
    verify_tls: Mapped[bool] = mapped_column(default=True)
    probe_host: Mapped[str] = mapped_column(String(255), default="")  # empty = host of base_url
    tls_port: Mapped[int] = mapped_column(default=443)
    enabled: Mapped[bool] = mapped_column(default=True)
    status: Mapped[str] = mapped_column(String(16), default="unknown")  # unknown|ok|degraded|down
    last_ok_at: Mapped[datetime | None] = mapped_column(default=None)
    last_attempt_at: Mapped[datetime | None] = mapped_column(default=None)
    last_error: Mapped[str] = mapped_column(String(1024), default="")
    version: Mapped[str | None] = mapped_column(String(32), default=None)
    latency_ms: Mapped[float | None] = mapped_column(default=None)
    # agent mode: sha256 (hex) of the DER of the agent's current client certificate ('' = not enrolled)
    agent_cert_fp: Mapped[str] = mapped_column(String(64), default="", server_default="")
    agent_cert_not_after: Mapped[datetime | None] = mapped_column(default=None)
    # renewed certificate, promoted to current at its first use (the old one works until then)
    agent_next_cert_fp: Mapped[str] = mapped_column(String(64), default="", server_default="")
    agent_enroll_hash: Mapped[str] = mapped_column(String(64), default="", server_default="")  # sha256, single use
    agent_enroll_expires: Mapped[datetime | None] = mapped_column(default=None)
    agent_ip: Mapped[str] = mapped_column(String(64), default="", server_default="")
    agent_version: Mapped[str] = mapped_column(String(32), default="", server_default="")
    silenced_until: Mapped[datetime | None] = mapped_column(default=None)  # alerts muted until then (UTC)
    snapshots: Mapped[list["Snapshot"]] = relationship(cascade="all, delete-orphan")
    probes: Mapped[list["CertProbe"]] = relationship(cascade="all, delete-orphan")
    tags: Mapped[list[Tag]] = relationship(secondary=instance_tags, order_by=Tag.name, lazy="selectin")

    @property
    def is_agent(self) -> bool:
        return self.connection == "agent"

    @property
    def probe_target(self) -> str:
        return self.probe_host or urlparse(self.base_url).hostname or ""


class Snapshot(Base):
    """Last known state per (instance, type)."""
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


class Setting(Base):
    """Small key/value store (the agent certificate authority lives here, its key encrypted)."""
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, default="")


alert_channel_tags = Table(
    "alert_channel_tags", Base.metadata,
    Column("channel_id", ForeignKey("alert_channels.id", ondelete="CASCADE"), primary_key=True),
    Column("tag_id", ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True),
)


class AlertChannel(Base):
    """One alert destination: a list of e-mail recipients or a webhook, filtered by tags and events."""
    __tablename__ = "alert_channels"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    kind: Mapped[str] = mapped_column(String(8))  # email | webhook
    enabled: Mapped[bool] = mapped_column(default=True)
    lang: Mapped[str] = mapped_column(String(5), default="en", server_default="en")
    events: Mapped[str] = mapped_column(String(64), default="down,degraded,certificate",
                                        server_default="down,degraded,certificate")  # down|degraded|certificate|version
    recipients: Mapped[str] = mapped_column(Text, default="", server_default="")  # email: one address per line
    webhook_url: Mapped[str] = mapped_column(String(512), default="", server_default="")
    webhook_secret_enc: Mapped[str] = mapped_column(String(512), default="", server_default="")  # Fernet
    created_at: Mapped[datetime] = mapped_column(default=utcnow)
    tags: Mapped[list[Tag]] = relationship(secondary=alert_channel_tags, order_by=Tag.name, lazy="selectin")

    def has_event(self, name: str) -> bool:
        return name in self.events.split(",")


class AlertState(Base):
    """What was last notified for one subject, and the pending change waiting for confirmation."""
    __tablename__ = "alert_state"
    __table_args__ = (UniqueConstraint("kind", "instance_id", "subject"),)
    id: Mapped[int] = mapped_column(primary_key=True)
    kind: Mapped[str] = mapped_column(String(8))  # status | cert | version
    instance_id: Mapped[int] = mapped_column(ForeignKey("instances.id", ondelete="CASCADE"))
    subject: Mapped[str] = mapped_column(String(255), default="")  # domain for certificates
    notified: Mapped[str] = mapped_column(String(64), default="")  # status / cert zone / version last notified
    pending: Mapped[str] = mapped_column(String(64), default="")
    pending_count: Mapped[int] = mapped_column(default=0)
    notified_at: Mapped[datetime | None] = mapped_column(default=None)


class AlertLog(Base):
    """Send log: one row per channel and message (kept after the channel is deleted)."""
    __tablename__ = "alert_log"
    id: Mapped[int] = mapped_column(primary_key=True)
    at: Mapped[datetime] = mapped_column(default=utcnow)
    channel_id: Mapped[int | None] = mapped_column(ForeignKey("alert_channels.id", ondelete="SET NULL"), default=None)
    channel_name: Mapped[str] = mapped_column(String(64), default="")
    events: Mapped[str] = mapped_column(String(255), default="")
    instances: Mapped[str] = mapped_column(String(255), default="")
    ok: Mapped[bool] = mapped_column(default=False)
    error: Mapped[str] = mapped_column(String(512), default="")
