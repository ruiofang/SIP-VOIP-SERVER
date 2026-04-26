"""进程入口：在同一事件循环里启动 SIP UDP 服务器与 FastAPI HTTP 服务器。"""
from __future__ import annotations

import asyncio
import ipaddress
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


def _warn_public_host() -> None:
    log = logging.getLogger("boot")
    relay_mode = "sticky" if settings.rtp_sticky_mode else "pool"
    log.info(
        "PUBLIC_HOST=%s SIP=%s/%s API=%s RTP=%s-%s mode=%s",
        settings.public_host,
        settings.sip_host,
        settings.sip_port,
        settings.api_port,
        settings.rtp_port_min,
        settings.rtp_port_max,
        relay_mode,
    )
    try:
        ip = ipaddress.ip_address(settings.public_host)
    except ValueError:
        return
    if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        log.warning(
            "PUBLIC_HOST=%s 不是公网可达地址；SIP/SDP 将向客户端宣告这个地址，公网终端通常无法回送媒体。",
            settings.public_host,
        )


async def _main() -> None:
    _setup_logging()
    _warn_public_host()
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
