"""Application configuration loaded from environment variables."""

from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime settings for VPN Controler."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    LOG_LEVEL: str = "INFO"

    # AdGuard Home REST API
    ADGUARD_URL: str = "http://adguard:3000"
    ADGUARD_USER: str = "admin"
    ADGUARD_PASSWORD: str = ""

    # Host & Tailscale Mesh node metadata
    HOST_LAN_IP: str = "192.168.178.65"
    HOST_TAILSCALE_IP: str = "100.107.4.120"
    TAILSCALE_DNS_NAME: str = "petroprog.tail703e6c.ts.net"
    ADGUARD_PUBLIC_PORT: int = 3053
    HTTPS_PWA_URL: str = "https://petroprog.tail703e6c.ts.net:8446"
    TAILSCALE_SOCK_PATH: str = "/var/run/tailscale/tailscaled.sock"

    # Explicit network timeouts & caches
    ADGUARD_TIMEOUT_SECONDS: float = 8.0
    TAILSCALE_TIMEOUT_SECONDS: float = 4.0
    DOH_PROBE_TIMEOUT_SECONDS: float = 3.0
    DOH_PROBE_CACHE_SECONDS: int = 60
    TAILSCALE_PING_CACHE_SECONDS: int = 30


@lru_cache
def get_settings() -> Settings:
    """Return cached settings singleton."""
    return Settings()


settings = get_settings()
