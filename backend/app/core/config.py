from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    PROJECT_NAME: str = "ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)"
    VERSION: str = "2.0.0"
    API_V1_PREFIX: str = "/api"
    
    # Database Configuration
    DATABASE_URL: str = Field(
        default="sqlite:///./ecdat.db",
        description="SQLAlchemy database connection URI"
    )
    
    # Redis & Celery
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URI"
    )
    
    # CORS Configuration
    CORS_ORIGINS: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "*"
    ]
    
    # Gemini AI configuration
    GEMINI_API_KEYS: str = Field(
        default="",
        description="Comma-separated Gemini API keys for AI assistant"
    )
    GEMINI_MODEL: str = Field(
        default="gemini-3.6-flash",
        description="Primary Gemini model"
    )
    GEMINI_MODEL_FALLBACK: str = Field(
        default="gemini-3.5-flash",
        description="Fallback Gemini model"
    )

    # Supabase Auth Configuration
    SUPABASE_URL: str = Field(
        default="",
        description="Supabase Project URL"
    )
    SUPABASE_JWT_SECRET: str = Field(
        default="",
        description="Supabase JWT secret or signing key for token verification"
    )
    REQUIRE_AUTH: bool = Field(
        default=False,
        description="Whether to enforce strict 401 on unauthenticated requests"
    )

    model_config = SettingsConfigDict(
        env_file=(".env", "../.env"),
        extra="ignore"
    )

settings = Settings()
