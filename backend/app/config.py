"""Application configuration using Pydantic Settings."""

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    """Runtime settings for NetSentinel."""

    model_config = SettingsConfigDict(
        env_prefix="NETSENTINEL_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "NetSentinel"
    app_version: str = "0.1.0"
    host: str = "127.0.0.1"
    port: int = 8000

    db_path: Path = BASE_DIR / "data" / "netsentinel.db"
    snort_rules_path: Path = BASE_DIR / "rules" / "default.rules"

    # Safe-by-default Active Response controls
    dry_run: bool = True
    auto_block_enabled: bool = False
    auto_block_threshold: Literal["high", "critical"] = "critical"
    block_ttl_seconds: int = 3600
    whitelist_ips: list[str] = Field(default_factory=lambda: ["127.0.0.1", "::1"])

    # Security & resource limits
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:4173",
            "http://127.0.0.1:4173",
        ]
    )
    max_scan_prefix: int = 20
    max_rules_file_bytes: int = 262_144
    live_packet_buffer_size: int = 300
    snmp_poll_interval_seconds: int = 5
    capture_interface: str | None = None


settings = Settings()
