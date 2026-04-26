"""UDP RTP 媒体中继。

设计：
  - 端口池：从 [rtp_port_min, rtp_port_max] 中按 偶数=RTP / 奇数=RTCP 成对分配。
  - 每路通话分配两组 (rtp, rtcp) socket：A 侧、B 侧。
    * 主叫的媒体包发送到 A 侧端口，由本中继转发到 B 侧学到的远端地址。
    * 被叫的媒体包发送到 B 侧端口，由本中继转发到 A 侧学到的远端地址。
  - 远端地址采用 *symmetric RTP* 学习：以收到的第一个数据包源地址为准，
    天然兼容大多数 NAT 场景，无需 STUN。
  - 没有任何 RTP 包解析（不解 payload type、不解 SSRC），单纯做包级转发。
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Tuple

logger = logging.getLogger("rtp")

Address = Tuple[str, int]


class _LegProtocol(asyncio.DatagramProtocol):
    """单条腿（一对 RTP+RTCP socket）的数据报协议处理。

    一个 RelayLeg 持有两个 _LegProtocol：rtp_proto, rtcp_proto。
    """

    def __init__(self, leg: "RelayLeg", is_rtcp: bool) -> None:
        self.leg = leg
        self.is_rtcp = is_rtcp
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: Address) -> None:  # type: ignore[override]
        self.leg.on_packet(data, addr, self.is_rtcp)

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        logger.debug("relay udp error: %s", exc)


@dataclass
class RelayLeg:
    """一条中继腿。

    远端学到地址前，本腿不主动转发；学到后，本腿收到的包会写入 *对端* 腿的远端地址。
    """
    name: str                                   # "A" / "B"
    rtp_port: int
    rtcp_port: int
    rtp_proto: _LegProtocol = field(init=False)
    rtcp_proto: _LegProtocol = field(init=False)
    learned_rtp: Optional[Address] = None       # 本腿对端（客户端）真实媒体地址
    learned_rtcp: Optional[Address] = None
    peer_leg: Optional["RelayLeg"] = None
    bytes_in: int = 0
    bytes_out: int = 0
    pkts_in: int = 0
    pkts_out: int = 0
    last_recv_ts: float = 0.0

    def on_packet(self, data: bytes, src: Address, is_rtcp: bool) -> None:
        # 学习源地址
        if is_rtcp:
            if self.learned_rtcp != src:
                self.learned_rtcp = src
                logger.debug("[relay %s] learned RTCP src=%s:%s", self.name, *src)
        else:
            if self.learned_rtp != src:
                self.learned_rtp = src
                logger.debug("[relay %s] learned RTP src=%s:%s", self.name, *src)

        self.bytes_in += len(data)
        self.pkts_in += 1
        self.last_recv_ts = time.time()

        peer = self.peer_leg
        if peer is None:
            return
        # 转发到对端腿学到的客户端地址（对端腿的远端 = 对端客户端）
        target = peer.learned_rtcp if is_rtcp else peer.learned_rtp
        if target is None:
            # 还没学到对端地址 — 先丢弃
            return
        proto = peer.rtcp_proto if is_rtcp else peer.rtp_proto
        if proto.transport is None:
            return
        try:
            proto.transport.sendto(data, target)
            peer.bytes_out += len(data)
            peer.pkts_out += 1
        except OSError as e:
            logger.debug("relay sendto err: %s", e)

    def close(self) -> None:
        if self.rtp_proto.transport:
            self.rtp_proto.transport.close()
        if self.rtcp_proto.transport:
            self.rtcp_proto.transport.close()


@dataclass
class RelaySession:
    call_id: str
    leg_a: RelayLeg
    leg_b: RelayLeg
    public_host: str
    created_at: float = field(default_factory=time.time)

    @property
    def a_rtp_port(self) -> int:
        return self.leg_a.rtp_port

    @property
    def b_rtp_port(self) -> int:
        return self.leg_b.rtp_port

    def close(self) -> None:
        self.leg_a.close()
        self.leg_b.close()

    def stats(self) -> dict:
        return {
            "call_id": self.call_id,
            "duration": int(time.time() - self.created_at),
            "leg_a": {
                "port": self.leg_a.rtp_port,
                "remote": self.leg_a.learned_rtp,
                "pkts_in": self.leg_a.pkts_in,
                "pkts_out": self.leg_a.pkts_out,
                "bytes_in": self.leg_a.bytes_in,
                "bytes_out": self.leg_a.bytes_out,
            },
            "leg_b": {
                "port": self.leg_b.rtp_port,
                "remote": self.leg_b.learned_rtp,
                "pkts_in": self.leg_b.pkts_in,
                "pkts_out": self.leg_b.pkts_out,
                "bytes_in": self.leg_b.bytes_in,
                "bytes_out": self.leg_b.bytes_out,
            },
        }


class RtpRelayManager:
    def __init__(
        self,
        host: str,
        public_host: str,
        port_min: int,
        port_max: int,
        *,
        sticky_mode: bool = False,
        sticky_port: Optional[int] = None,
    ) -> None:
        self.host = host
        self.public_host = public_host
        self.port_min = port_min if port_min % 2 == 0 else port_min + 1
        self.port_max = port_max
        self._next = self.port_min
        self._sessions: Dict[str, RelaySession] = {}
        self._lock = asyncio.Lock()
        self.sticky_mode = sticky_mode
        sp = sticky_port if sticky_port is not None else self.port_min
        self.sticky_port = sp if sp % 2 == 0 else sp + 1

    @staticmethod
    def _init_placeholder_leg(leg: RelayLeg, *, name: str, rtp_port: int, rtcp_port: int) -> None:
        """Initialize a placeholder leg so early packets won't hit missing attributes."""
        leg.name = name
        leg.rtp_port = rtp_port
        leg.rtcp_port = rtcp_port
        leg.learned_rtp = None
        leg.learned_rtcp = None
        leg.peer_leg = None
        leg.bytes_in = 0
        leg.bytes_out = 0
        leg.pkts_in = 0
        leg.pkts_out = 0
        leg.last_recv_ts = 0.0

    async def _allocate_pair(self) -> Tuple[asyncio.DatagramTransport, asyncio.DatagramTransport,
                                            int, int, _LegProtocol, _LegProtocol]:
        """分配相邻偶/奇端口对（RTP/RTCP）。"""
        loop = asyncio.get_event_loop()
        attempts = 0
        max_attempts = (self.port_max - self.port_min) // 2 + 1
        while attempts < max_attempts:
            port = self._next
            self._next += 2
            if self._next > self.port_max - 1:
                self._next = self.port_min
            attempts += 1
            try:
                # 临时占位 leg 引用，稍后回填
                placeholder_leg = RelayLeg.__new__(RelayLeg)
                self._init_placeholder_leg(
                    placeholder_leg, name="P", rtp_port=port, rtcp_port=port + 1
                )
                rtp_proto = _LegProtocol(placeholder_leg, False)
                rtcp_proto = _LegProtocol(placeholder_leg, True)
                rtp_t, _ = await loop.create_datagram_endpoint(
                    lambda: rtp_proto, local_addr=(self.host, port))
                try:
                    rtcp_t, _ = await loop.create_datagram_endpoint(
                        lambda: rtcp_proto, local_addr=(self.host, port + 1))
                except OSError:
                    rtp_t.close()
                    continue
                return rtp_t, rtcp_t, port, port + 1, rtp_proto, rtcp_proto
            except OSError:
                continue
        raise RuntimeError("RTP port pool exhausted")

    async def _allocate_fixed_pair(
        self, port: int
    ) -> Tuple[asyncio.DatagramTransport, asyncio.DatagramTransport, int, int, _LegProtocol, _LegProtocol]:
        """Allocate a fixed RTP/RTCP port pair."""
        loop = asyncio.get_event_loop()
        placeholder_leg = RelayLeg.__new__(RelayLeg)
        self._init_placeholder_leg(
            placeholder_leg, name="P", rtp_port=port, rtcp_port=port + 1
        )
        rtp_proto = _LegProtocol(placeholder_leg, False)
        rtcp_proto = _LegProtocol(placeholder_leg, True)
        rtp_t, _ = await loop.create_datagram_endpoint(
            lambda: rtp_proto, local_addr=(self.host, port)
        )
        try:
            rtcp_t, _ = await loop.create_datagram_endpoint(
                lambda: rtcp_proto, local_addr=(self.host, port + 1)
            )
        except OSError:
            rtp_t.close()
            raise
        return rtp_t, rtcp_t, port, port + 1, rtp_proto, rtcp_proto

    async def allocate(self, call_id: str) -> RelaySession:
        async with self._lock:
            if call_id in self._sessions:
                return self._sessions[call_id]

            if self.sticky_mode and self._sessions:
                raise RuntimeError("sticky RTP mode supports one active call")

            if self.sticky_mode:
                (rtp_a_t, rtcp_a_t, port_a, _, rtp_a_p, rtcp_a_p) = await self._allocate_fixed_pair(self.sticky_port)
                (rtp_b_t, rtcp_b_t, port_b, _, rtp_b_p, rtcp_b_p) = await self._allocate_fixed_pair(self.sticky_port + 2)
            else:
                (rtp_a_t, rtcp_a_t, port_a, _, rtp_a_p, rtcp_a_p) = await self._allocate_pair()
                (rtp_b_t, rtcp_b_t, port_b, _, rtp_b_p, rtcp_b_p) = await self._allocate_pair()

            leg_a = RelayLeg("A", port_a, port_a + 1, rtp_a_p, rtcp_a_p)
            leg_b = RelayLeg("B", port_b, port_b + 1, rtp_b_p, rtcp_b_p)
            # 回填 leg 引用
            rtp_a_p.leg = leg_a
            rtcp_a_p.leg = leg_a
            rtp_b_p.leg = leg_b
            rtcp_b_p.leg = leg_b
            leg_a.peer_leg = leg_b
            leg_b.peer_leg = leg_a

            session = RelaySession(call_id=call_id, leg_a=leg_a, leg_b=leg_b,
                                   public_host=self.public_host)
            self._sessions[call_id] = session
            mode = "sticky" if self.sticky_mode else "pool"
            logger.info("[relay alloc] call=%s A=%d B=%d mode=%s", call_id, port_a, port_b, mode)
            return session

    def get(self, call_id: str) -> Optional[RelaySession]:
        return self._sessions.get(call_id)

    async def release(self, call_id: str) -> None:
        async with self._lock:
            s = self._sessions.pop(call_id, None)
            if s:
                s.close()
                logger.info("[relay free] call=%s A=%d B=%d", call_id, s.a_rtp_port, s.b_rtp_port)

    def hint_remote(self, call_id: str, leg: str, rtp_addr: Address) -> None:
        """从 SDP 学到的远端候选地址（提前写入），后续仍以 symmetric RTP 学到的为准。"""
        s = self._sessions.get(call_id)
        if not s:
            return
        target_leg = s.leg_a if leg == "A" else s.leg_b
        if target_leg.learned_rtp is None:
            target_leg.learned_rtp = rtp_addr
            target_leg.learned_rtcp = (rtp_addr[0], rtp_addr[1] + 1)

    def list_sessions(self) -> list[dict]:
        return [s.stats() for s in self._sessions.values()]
