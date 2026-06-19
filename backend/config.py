from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    app_name: str = "Aegis API"
    version: str = "1.0.0"
    debug: bool = False

    database_url: str = "sqlite:///./aegis_cloud.db"

    jwt_secret: str = "change-this-to-a-secure-random-string"
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 1440

    google_client_id: Optional[str] = None
    stripe_api_key: Optional[str] = None
    stripe_webhook_secret: Optional[str] = None

    free_requests_per_day: int = 25
    medium_requests_per_day: int = 500
    ultimate_requests_per_day: int = 10000

    medium_price_monthly: float = 12.0
    ultimate_price_monthly: float = 39.0

    max_log_retention_days: int = 365

    allowed_origins: list = ["*"]

    class Config:
        env_file = ".env"


settings = Settings()
