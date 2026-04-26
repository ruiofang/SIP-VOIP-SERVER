"""配置加载（基于 pydantic-settings + .env）。"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # 监听
    sip_host: str = "0.0.0.0"
    sip_port: int = 5060
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # 对外
    public_host: str = "127.0.0.1"
    public_sip_port: int = 5060

    # RTP 媒体中继
    rtp_port_min: int = 20000
    rtp_port_max: int = 20199

    # 数据库
    database_url: str = "sqlite+aiosqlite:///./sip.db"

    # 安全
    jwt_secret: str = "change-me"
    sip_realm: str = "sip.example.com"
    admin_default_user: str = "admin"
    admin_default_pass: str = "admin123"

    # 媒体
    voice_storage_dir: str = "./voice_storage"
    voice_max_bytes: int = 2 * 1024 * 1024

    log_level: str = "INFO"

    @property
    def voice_dir_path(self) -> Path:
        p = Path(self.voice_storage_dir)
        p.mkdir(parents=True, exist_ok=True)
        return p


@lru_cache
def get_settings() -> Settings:
    return Settings()
