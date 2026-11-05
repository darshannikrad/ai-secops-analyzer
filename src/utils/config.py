"""Application configuration module using pydantic-settings."""

from enum import Enum
from functools import lru_cache
from typing import List, Optional, Union

from pydantic import BaseModel, Field, field_validator
try:
    from pydantic_settings import BaseSettings, SettingsConfigDict
except ImportError:
    class BaseSettings(BaseModel):  # type: ignore
        pass

    def SettingsConfigDict(**kwargs):  # type: ignore
        return kwargs


class LLMProvider(str, Enum):
    """Supported LLM providers."""

    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google"
    LOCAL = "local"
    OFFLINE = "offline"


class DetectionThresholds(BaseModel):
    """Detection thresholds configuration."""

    brute_force_failed_attempts: int = Field(
        default=5,
        ge=1,
        description="Number of failed auth attempts triggering brute force detection",
    )
    brute_force_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Time window in seconds for brute force detection",
    )
    port_scan_unique_ports: int = Field(
        default=15,
        ge=2,
        description="Unique destination ports targeted triggering port scan detection",
    )
    port_scan_window_seconds: int = Field(
        default=60,
        ge=1,
        description="Time window in seconds for port scan detection",
    )
    dos_request_rate_per_sec: float = Field(
        default=50.0,
        gt=0.0,
        description="Request rate per second triggering DoS detection",
    )
    dos_window_seconds: int = Field(
        default=30,
        ge=1,
        description="Time window in seconds for DoS detection",
    )
    data_exfil_bytes_threshold: int = Field(
        default=10_000_000,
        ge=1024,
        description="Bytes transferred out triggering data exfiltration alert (default: 10MB)",
    )
    data_exfil_window_seconds: int = Field(
        default=300,
        ge=1,
        description="Time window in seconds for data exfiltration detection",
    )
    statistical_anomaly_zscore: float = Field(
        default=3.0,
        gt=0.0,
        description="Modified Z-score threshold for statistical anomalies",
    )


class CorrelationWindowConfig(BaseModel):
    """Correlation engine window settings."""

    max_gap_seconds: int = Field(
        default=300,
        ge=1,
        description="Maximum seconds between related events to stay in same correlation group",
    )
    incident_merge_window_seconds: int = Field(
        default=900,
        ge=1,
        description="Window in seconds to merge related detections into an incident",
    )
    max_incident_duration_seconds: int = Field(
        default=86400,
        ge=60,
        description="Maximum lifespan duration of an active incident group (24 hours)",
    )


class Settings(BaseSettings):
    """Global application settings loaded from environment or .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # LLM Provider Configuration
    llm_provider: LLMProvider = Field(
        default=LLMProvider.OFFLINE,
        description="Active LLM provider mode",
    )
    openai_api_key: Optional[str] = Field(
        default=None,
        description="OpenAI API key if using openai provider",
    )
    anthropic_api_key: Optional[str] = Field(
        default=None,
        description="Anthropic API key if using anthropic provider",
    )
    google_api_key: Optional[str] = Field(
        default=None,
        description="Google API key if using google provider",
    )
    local_llm_url: str = Field(
        default="http://localhost:11434/api/generate",
        description="URL endpoint for local LLM inference",
    )
    local_llm_model: str = Field(
        default="llama3.2",
        description="Model name for local LLM inference",
    )

    # Application Settings
    app_host: str = Field(
        default="0.0.0.0",
        description="FastAPI application bind host",
    )
    app_port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="FastAPI application port",
    )
    database_url: str = Field(
        default="sqlite:///./secops_analyzer.db",
        description="Database connection URL",
    )
    log_level: str = Field(
        default="INFO",
        description="Logging level",
    )
    max_upload_size_mb: int = Field(
        default=100,
        ge=1,
        description="Maximum log file upload size in MB",
    )
    max_tool_calls_per_investigation: int = Field(
        default=20,
        ge=1,
        description="Safety ceiling for investigation agent tool invocations",
    )
    investigation_timeout_seconds: int = Field(
        default=120,
        ge=5,
        description="Investigation timeout in seconds",
    )

    # Security
    secret_key: str = Field(
        default="change-this-in-production",
        description="Secret key for signing sessions and tokens",
    )
    allowed_origins: Union[str, List[str]] = Field(
        default="http://localhost:8501,http://localhost:8000",
        description="Allowed CORS origins as comma-separated string or list",
    )

    # Data Retention
    max_analysis_age_days: int = Field(
        default=90,
        ge=1,
        description="Maximum age of analyses to retain in days",
    )
    max_stored_analyses: int = Field(
        default=100,
        ge=1,
        description="Maximum count of analyses stored in database",
    )

    # Embedded Domain Configs
    thresholds: DetectionThresholds = Field(
        default_factory=DetectionThresholds,
        description="Threshold configuration for detections",
    )
    correlation: CorrelationWindowConfig = Field(
        default_factory=CorrelationWindowConfig,
        description="Window configuration for correlation engine",
    )

    @field_validator("allowed_origins", mode="after")
    @classmethod
    def parse_allowed_origins(cls, value: Union[str, List[str]]) -> List[str]:
        """Normalize allowed origins into a list of strings."""
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Retrieve cached application settings singleton."""
    return Settings()
