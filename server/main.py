"""进程入口：在同一事件循环里启动 SIP UDP 服务器与 FastAPI HTTP 服务器。"""
from __future__ import annotations

import asyncio
import logging

import uvicorn

from .api import app
from .config import get_settings
from .sip_server import start_sip_server
from . import runtime

settings = get_settings()


def _setup_logging() -> None:
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
    )


async def _main() -> None:
    _setup_logging()
    transport, protocol = await start_sip_server()
    runtime.sip_protocol = protocol
    config = uvicorn.Config(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        access_log=False,
    )
    server = uvicorn.Server(config)
    try:
        await server.serve()
    finally:
        transport.close()


def main() -> None:
    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
