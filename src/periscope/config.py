from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PERISCOPE_", env_file=".env", extra="ignore")

    secret_key: str  # clé Fernet (base64 urlsafe 32 octets) ; python -c "from cryptography.fernet import Fernet;print(Fernet.generate_key().decode())"
    database_url: str = "sqlite:///./data/periscope.db"
    collector_enabled: bool = True
    poll_interval: int = 30
    probe_interval: int = 900
    http_timeout: float = 5.0
    stale_cycles: int = 3
    rp_id: str = "localhost"  # domaine WebAuthn
    rp_name: str = "Periscope for BunkerWeb"
    origins: list[str] = ["http://localhost:8000"]  # JSON dans l'env : PERISCOPE_ORIGINS='["https://periscope.example.com"]'
    cookie_secure: bool = True
    session_idle_seconds: int = 8 * 3600
    session_max_seconds: int = 24 * 3600


@lru_cache
def get_settings() -> Settings:
    return Settings()
