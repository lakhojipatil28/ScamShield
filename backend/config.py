"""
Configuration settings for ScamShield backend.
Supports environment variables with sensible defaults for local development.
"""
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # Application Info
    APP_NAME: str = "ScamShield"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: str = "development"
    DEBUG: bool = True

    # Server Configuration
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "*",
    ]

    # Google Gemini AI Configuration
    # Uses official google-genai SDK
    GEMINI_API_KEY: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")
    GEMINI_MODEL: str = Field(default="gemini-3.8-flash", alias="GEMINI_MODEL")
    GEMINI_TIMEOUT_SECONDS: float = 12.0
    GEMINI_MAX_RETRIES: int = 2

    # Risk Scoring Thresholds (Configurable)
    # 0 - 29: LOW
    # 30 - 59: MODERATE
    # 60 - 84: HIGH
    # 85 - 100: CRITICAL
    RISK_LOW_THRESHOLD: int = 29
    RISK_MODERATE_THRESHOLD: int = 59
    RISK_HIGH_THRESHOLD: int = 84

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # Storage and Persistence
    STORAGE_TYPE: str = "sqlite"  # "sqlite", "memory", or "firestore"
    SQLITE_DB_PATH: str = "scamshield.db"
    FIREBASE_PROJECT_ID: Optional[str] = None
    FIREBASE_CREDENTIALS_PATH: Optional[str] = None

    # Request limits
    MAX_TEXT_LENGTH: int = 25000
    MAX_IMAGE_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "extra": "ignore",
    }


settings = Settings()
