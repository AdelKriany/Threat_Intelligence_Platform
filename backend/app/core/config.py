from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables and .env files."""

    project_name: str = "ThreatLens"
    environment: str = "development"
    secret_key: str = "replace-me-with-a-secure-secret"
    database_url: str = "postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens"
    redis_url: str = "redis://localhost:6379/0"
    log_level: str = "INFO"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()
