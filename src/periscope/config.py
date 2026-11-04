from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PERISCOPE_", env_file=".env", extra="ignore")

    secret_key: str  # Fernet key (urlsafe base64, 32 bytes); python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
    database_url: str = "sqlite:///./data/periscope.db"
    collector_enabled: bool = True
    poll_interval: int = 30
    probe_interval: int = 900
    http_timeout: float = 5.0
    stale_cycles: int = 3
    rp_id: str = "localhost"  # domaine WebAuthn
    rp_name: str = "Periscope for BunkerWeb"
    origins: list[str] = ["http://localhost:8000"]  # JSON in the env: PERISCOPE_ORIGINS='["https://periscope.example.com"]'
    cookie_secure: bool = True
    session_idle_seconds: int = 8 * 3600
    session_max_seconds: int = 24 * 3600
    max_parallel: int = 20  # instances collected / probed at the same time
    max_parallel_probes: int = 50  # TLS handshakes in flight at the same time
    # Agent listener (mutual TLS), enabled when agent_public_url is set: the URL the agents use to
    # reach it, e.g. https://periscope-agents.example.com:8443 (its host goes in the server certificate).
    agent_public_url: str = ""
    agent_listen_host: str = "0.0.0.0"
    agent_listen_port: int = 8443
    agent_enroll_ttl: int = 24 * 3600  # validity of an enrollment token (s)
    agent_max_report_bytes: int = 8 * 1024 * 1024

    @field_validator("database_url")
    @classmethod
    def _postgres_driver(cls, v: str) -> str:
        """`postgresql://` (or `postgres://`) would make SQLAlchemy pick psycopg2: we ship psycopg 3."""
        for prefix in ("postgresql://", "postgres://"):
            if v.startswith(prefix):
                return "postgresql+psycopg://" + v.removeprefix(prefix)
        return v


@lru_cache
def get_settings() -> Settings:
    return Settings()
