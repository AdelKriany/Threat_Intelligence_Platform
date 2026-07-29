from pydantic import Field, field_validator
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
    enrichment_ttl_seconds: int = Field(default=86400, ge=60)
    enrichment_request_timeout_seconds: float = Field(default=10.0, gt=0, le=120)
    enrichment_max_retries: int = Field(default=2, ge=0, le=5)
    enrichment_batch_size: int = Field(default=100, ge=1, le=1000)
    enrichment_refresh_interval_minutes: int = Field(default=60, ge=1)
    enrichment_rate_limit_retry_seconds: int = Field(default=900, ge=30)
    enrichment_not_found_ttl_seconds: int = Field(default=21600, ge=60)
    enrichment_failure_retry_seconds: int = Field(default=900, ge=30)
    enrichment_retry_max_delay_seconds: float = Field(default=60.0, gt=0, le=300)
    nvd_enabled: bool = True
    nvd_api_key: str | None = None
    cisa_kev_enabled: bool = True
    cisa_kev_catalog_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    cisa_kev_ttl_seconds: int = Field(default=21600, ge=300)
    cisa_kev_refresh_interval_minutes: int = Field(default=360, ge=5)
    epss_enabled: bool = True
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_batch_size: int = Field(default=100, ge=1, le=100)
    epss_ttl_seconds: int = Field(default=86400, ge=3600)
    epss_refresh_interval_minutes: int = Field(default=1440, ge=60)
    abuseipdb_enabled: bool = False
    abuseipdb_api_key: str | None = None
    virustotal_enabled: bool = False
    virustotal_api_key: str | None = None

    @field_validator("cisa_kev_catalog_url", "epss_api_url")
    @classmethod
    def validate_provider_url(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("provider URLs must use HTTPS")
        return value

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
