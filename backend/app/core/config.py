"""Application configuration using pydantic-settings."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Global application settings loaded from environment variables."""

    APP_NAME: str = "Kynetic Sentra"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Groq configuration
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"


    # File upload limits
    MAX_FILE_SIZE_MB: int = 10
    MAX_CONTENT_LENGTH: int = 500_000  # characters

    # Log analysis
    LOG_CHUNK_SIZE: int = 5000  # lines per chunk
    MAX_LOG_LINES: int = 100_000

    # Rate limiting
    RATE_LIMIT_REQUESTS: int = 60
    RATE_LIMIT_WINDOW: int = 60  # seconds

    ALLOWED_FILE_EXTENSIONS: list[str] = [".txt", ".log", ".pdf", ".doc", ".docx"]

    model_config = SettingsConfigDict(env_file=".env", case_sensitive=True, extra="ignore")


settings = Settings()
