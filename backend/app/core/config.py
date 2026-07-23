from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env files."""

    project_name: str = "ThreatLens"
    environment: str = "development"
    secret_key: str = "replace-me-with-a-secure-secret"
    database_url: str = "postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens"
    redis_url: str = "redis://localhost:6379/0"
    log_level: str = "INFO"
    enrichment_enabled: bool = False
    enrichment_ttl_seconds: int = 86400
    enrichment_request_timeout_seconds: float = 10.0
    enrichment_max_retries: int = 2
    enrichment_batch_size: int = 100
    enrichment_refresh_interval_minutes: int = 60
    nvd_enabled: bool = True
    nvd_api_key: str | None = None
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str | None = None
    virustotal_enabled: bool = False
    virustotal_api_key: str | None = None

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
