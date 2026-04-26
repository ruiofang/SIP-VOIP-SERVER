"""数据库连接与会话管理。"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from .config import get_settings
from .models import Base

settings = get_settings()

engine = create_async_engine(settings.database_url, future=True, pool_pre_ping=True)
SessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


# 已发布版本之后新增的列：在启动时自动补齐，避免破坏旧数据库。
# 形如 (table, column, ddl_type, default_sql)
_MIGRATIONS: list[tuple[str, str, str, str]] = [
    ("messages", "status", "VARCHAR(16)", "'pending'"),
    ("messages", "attempts", "INTEGER", "0"),
    ("messages", "read_at", "DATETIME", "NULL"),
    ("messages", "last_attempt_at", "DATETIME", "NULL"),
]


def _sync_migrate(conn) -> None:
    dialect = conn.dialect.name
    for table, col, ddl_type, default_sql in _MIGRATIONS:
        if dialect == "sqlite":
            rows = conn.exec_driver_sql(f"PRAGMA table_info({table})").fetchall()
            existing = {r[1] for r in rows}  # name in column 1
        else:
            try:
                rows = conn.exec_driver_sql(
                    "SELECT COLUMN_NAME FROM information_schema.columns "
                    f"WHERE table_name='{table}'"
                ).fetchall()
                existing = {r[0] for r in rows}
            except Exception:
                existing = set()
        if col in existing:
            continue
        default_clause = "" if default_sql == "NULL" else f" DEFAULT {default_sql}"
        try:
            conn.exec_driver_sql(
                f"ALTER TABLE {table} ADD COLUMN {col} {ddl_type}{default_clause}"
            )
        except Exception:
            # 可能已经存在或并发迁移，忽略
            pass


async def init_db() -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(_sync_migrate)
        # 兼容旧记录：delivered=True 的消息状态置为 delivered
        await conn.exec_driver_sql(
            "UPDATE messages SET status='delivered' "
            "WHERE delivered=1 AND (status IS NULL OR status='pending')"
        )


@asynccontextmanager
async def session_scope() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_session() -> AsyncIterator[AsyncSession]:
    async with SessionLocal() as session:
        yield session
