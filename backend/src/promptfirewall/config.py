from functools import lru_cache

from pydantic import AliasChoices, Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="PROMPTFIREWALL_", env_file=".env", extra="ignore", populate_by_name=True,
    )

    environment: str = Field(
        default="development",
        validation_alias=AliasChoices("PROMPTFIREWALL_ENV", "PROMPTFIREWALL_ENVIRONMENT"),
    )
    database_url: str = "sqlite+aiosqlite:///./promptfirewall.db"
    max_matrix_size: int = Field(default=500, ge=1, le=10_000)
    worker_count: int = Field(default=2, ge=1, le=16)
    log_level: str = "INFO"
    api_key: SecretStr | None = Field(default=None, min_length=16)
    model_provider: str = Field(
        default="mock",
        validation_alias=AliasChoices("MODEL_PROVIDER", "PROMPTFIREWALL_MODEL_PROVIDER"),
    )
    model_name: str = Field(
        default="promptfirewall-mock-1",
        validation_alias=AliasChoices("MODEL_NAME", "PROMPTFIREWALL_MODEL_NAME"),
    )
    model_base_url: str | None = Field(
        default=None,
        validation_alias=AliasChoices("MODEL_BASE_URL", "PROMPTFIREWALL_MODEL_BASE_URL"),
    )
    model_api_key: SecretStr | None = Field(
        default=None,
        validation_alias=AliasChoices("MODEL_API_KEY", "PROMPTFIREWALL_MODEL_API_KEY"),
    )
    model_temperature: float = Field(
        default=0.0,
        ge=0,
        le=2,
        validation_alias=AliasChoices("MODEL_TEMPERATURE", "PROMPTFIREWALL_MODEL_TEMPERATURE"),
    )
    model_timeout_seconds: float = Field(
        default=30.0,
        gt=0,
        le=120,
        validation_alias=AliasChoices(
            "MODEL_TIMEOUT_SECONDS", "PROMPTFIREWALL_MODEL_TIMEOUT_SECONDS",
        ),
    )
    model_max_retries: int = Field(
        default=2,
        ge=0,
        le=5,
        validation_alias=AliasChoices("MODEL_MAX_RETRIES", "PROMPTFIREWALL_MODEL_MAX_RETRIES"),
    )
    model_retry_backoff_seconds: float = Field(
        default=0.2,
        ge=0,
        le=30,
        validation_alias=AliasChoices(
            "MODEL_RETRY_BACKOFF_SECONDS",
            "PROMPTFIREWALL_MODEL_RETRY_BACKOFF_SECONDS",
        ),
    )

    @model_validator(mode="after")
    def require_production_auth(self) -> "Settings":
        if self.environment.casefold() == "production" and self.api_key is None:
            raise ValueError("PROMPTFIREWALL_API_KEY is required in production")
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
