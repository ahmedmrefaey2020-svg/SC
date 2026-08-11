import os
from functools import lru_cache
from dotenv import load_dotenv

load_dotenv()


class Settings:
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./ips_data.db")
    API_DATABASE: str = os.getenv("API_DATABASE", "sqlite:///./api_data.db")
    BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "3000"))
    BATCH_FLUSH_INTERVAL: float = float(os.getenv("BATCH_FLUSH_INTERVAL", "2.0"))
    SNIFF_TIMEOUT: int = int(os.getenv("SNIFF_TIMEOUT", "2"))
    BLOCKED_IP_CACHE_TTL: int = int(os.getenv("BLOCKED_IP_CACHE_TTL", "60"))
    DB_WRITER_INTERVAL: float = float(os.getenv("DB_WRITER_INTERVAL", "1.0"))
    MAX_RECENT_FLOWS: int = int(os.getenv("MAX_RECENT_FLOWS", "100"))
    SETTINGS_CACHE_TTL: int = int(os.getenv("SETTINGS_CACHE_TTL", "5"))
    AGENT_OFFLINE_SECONDS: float = float(os.getenv("AGENT_OFFLINE_SECONDS", "15"))
    API_RATE_LIMIT_SETTINGS: str = os.getenv("API_RATE_LIMIT_SETTINGS", "20/minute")
    API_RATE_LIMIT_INGEST: str = os.getenv("API_RATE_LIMIT_INGEST", "300/minute")
    API_RATE_LIMIT_BLOCK: str = os.getenv("API_RATE_LIMIT_BLOCK", "60/minute")
    ALLOWED_ORIGINS: str = os.getenv("ALLOWED_ORIGINS", "*")
    ALLOWED_HOSTS: str = os.getenv("ALLOWED_HOSTS", "*")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
