"""SDP 解析与重写。

只关注两件事：
  - c=IN IP4 <addr>            （连接地址）
  - m=audio <port> <transport> <fmts...>   （媒体行）

目标：把客户端公布的媒体地址/端口替换成中继的公网地址/分配端口；同时返回原值，
让上层把它写入 RTP 中继的 hint_remote。
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class SdpInfo:
    media_ip: Optional[str] = None
    media_port: Optional[int] = None


def parse_sdp(body: bytes) -> SdpInfo:
    info = SdpInfo()
    text = body.decode("utf-8", errors="replace")
    # 优先取 audio 行；若有 m=audio 则用其端口
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("m=audio"):
            parts = line.split()
            if len(parts) >= 2:
                try:
                    info.media_port = int(parts[1])
                except ValueError:
                    pass
        elif line.startswith("c=IN IP4"):
            parts = line.split()
            if len(parts) >= 3:
                info.media_ip = parts[2].split("/")[0]
    return info


_C_RE = re.compile(rb"^c=IN IP4 [^\r\n]+", re.MULTILINE)
_M_AUDIO_RE = re.compile(rb"^(m=audio )(\d+)( .*)$", re.MULTILINE)


def rewrite_sdp(body: bytes, new_ip: str, new_port: int) -> Tuple[bytes, SdpInfo]:
    """重写 c= 与 m=audio 端口，返回新 body 与原始信息。"""
    info = parse_sdp(body)
    new_c = f"c=IN IP4 {new_ip}".encode("ascii")
    body2 = _C_RE.sub(new_c, body)
    body2 = _M_AUDIO_RE.sub(
        lambda m: m.group(1) + str(new_port).encode("ascii") + m.group(3),
        body2,
    )
    return body2, info
