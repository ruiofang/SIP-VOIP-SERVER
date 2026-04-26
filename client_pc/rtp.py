"""RTP 收发 + 可选麦克风/扬声器 I/O。

- 8 kHz, 单声道, 20 ms / 帧 (160 样本)
- 编解码: PCMU (PT=0) 或 PCMA (PT=8)
- 麦克风→编码→UDP；UDP→解码→扬声器
- 没有 sounddevice 时自动降级为静默 RTP (仍发包以保持 NAT 通道)
"""
from __future__ import annotations

import asyncio
import logging
import os
import random
import struct
import time
from typing import Optional, Tuple

try:
    from . import g711  # type: ignore
except ImportError:  # standalone 运行
    import g711  # type: ignore


log = logging.getLogger("rtp")

SAMPLE_RATE = 8000
FRAME_MS = 20
FRAME_SAMPLES = SAMPLE_RATE * FRAME_MS // 1000  # 160
FRAME_BYTES_PCM16 = FRAME_SAMPLES * 2

PT_PCMU = 0
PT_PCMA = 8


def _build_rtp(seq: int, ts: int, ssrc: int, pt: int, payload: bytes) -> bytes:
    # V=2, P=0, X=0, CC=0
    b0 = 0x80
    b1 = pt & 0x7F
    return struct.pack("!BBHII", b0, b1, seq & 0xFFFF, ts & 0xFFFFFFFF, ssrc & 0xFFFFFFFF) + payload


def _parse_rtp(pkt: bytes) -> Optional[Tuple[int, bytes]]:
    if len(pkt) < 12:
        return None
    b0 = pkt[0]
    if (b0 >> 6) != 2:
        return None
    cc = b0 & 0x0F
    has_ext = (b0 >> 4) & 0x01
    pt = pkt[1] & 0x7F
    offset = 12 + cc * 4
    if has_ext:
        if len(pkt) < offset + 4:
            return None
        ext_len = struct.unpack("!H", pkt[offset + 2:offset + 4])[0]
        offset += 4 + ext_len * 4
    if len(pkt) < offset:
        return None
    return pt, pkt[offset:]


class _RtpProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_packet):
        self.on_packet = on_packet
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport  # type: ignore

    def datagram_received(self, data, addr):
        self.on_packet(data, addr)

    def error_received(self, exc):
        log.debug("RTP error: %s", exc)


class RtpSession:
    def __init__(self, *, local_port: int, codec: str = "pcmu", use_audio: bool = True):
        self.local_port = local_port
        self.codec = codec
        self.payload_type = PT_PCMA if codec == "pcma" else PT_PCMU
        self.use_audio = use_audio
        self.remote: Optional[Tuple[str, int]] = None
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._proto: Optional[_RtpProtocol] = None
        self._send_task: Optional[asyncio.Task] = None
        self._seq = random.randint(0, 0xFFFF)
        self._ts = random.randint(0, 0xFFFFFFFF)
        self._ssrc = random.randint(0, 0xFFFFFFFF)
        self._closed = False
        # audio
        self._in_stream = None  # mic
        self._out_stream = None  # speaker
        self._mic_q: asyncio.Queue = asyncio.Queue(maxsize=50)
        self._spk_buf = bytearray()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # stats
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.pkts_sent = 0
        self.pkts_recv = 0

    @property
    def actual_local_port(self) -> int:
        if self._transport is None:
            return self.local_port
        sock = self._transport.get_extra_info("socket")
        return sock.getsockname()[1] if sock else self.local_port

    async def start(self, local_host: str = "0.0.0.0"):
        self._loop = asyncio.get_running_loop()
        self._transport, self._proto = await self._loop.create_datagram_endpoint(
            lambda: _RtpProtocol(self._on_packet),
            local_addr=(local_host, self.local_port),
        )
        if self.use_audio:
            self._open_audio()
        self._send_task = self._loop.create_task(self._sender_loop())
        log.info("RTP listening on %s (codec=%s)", self.actual_local_port, self.codec)

    def _open_audio(self):
        try:
            import sounddevice as sd  # type: ignore
            import numpy as np  # type: ignore
        except Exception as e:
            log.warning("sounddevice/numpy 不可用，禁用音频：%s", e)
            self.use_audio = False
            return

        loop = self._loop

        def _mic_cb(indata, frames, time_info, status):
            if status:
                log.debug("mic status: %s", status)
            try:
                # indata: numpy int16 [frames, 1]
                data = bytes(indata)
                loop.call_soon_threadsafe(self._enqueue_mic, data)
            except Exception as e:
                log.debug("mic cb err: %s", e)

        def _spk_cb(outdata, frames, time_info, status):
            need = frames * 2
            if len(self._spk_buf) >= need:
                outdata[:] = bytes(self._spk_buf[:need])
                del self._spk_buf[:need]
            else:
                got = bytes(self._spk_buf)
                self._spk_buf.clear()
                outdata[:len(got)] = got
                # zero pad
                if len(got) < need:
                    outdata[len(got):] = b"\x00" * (need - len(got))

        try:
            self._in_stream = sd.RawInputStream(
                samplerate=SAMPLE_RATE, blocksize=FRAME_SAMPLES,
                channels=1, dtype="int16", callback=_mic_cb,
            )
            self._out_stream = sd.RawOutputStream(
                samplerate=SAMPLE_RATE, blocksize=FRAME_SAMPLES,
                channels=1, dtype="int16", callback=_spk_cb,
            )
            self._in_stream.start()
            self._out_stream.start()
        except Exception as e:
            log.warning("打开音频设备失败：%s（降级为静默 RTP）", e)
            self.use_audio = False
            self._in_stream = self._out_stream = None

    def _enqueue_mic(self, pcm: bytes):
        if self._mic_q.full():
            try:
                self._mic_q.get_nowait()
            except Exception:
                pass
        try:
            self._mic_q.put_nowait(pcm)
        except Exception:
            pass

    def set_remote(self, host: str, port: int):
        self.remote = (host, port)
        log.info("RTP remote = %s:%s", host, port)

    def _on_packet(self, data: bytes, addr):
        # 学习对端地址（symmetric RTP）
        if self.remote is None or self.remote[0] in ("0.0.0.0", "127.0.0.1") or self.remote != addr:
            # 仅当尚未设置或地址不同时学习；服务端中继可能用 0.0.0.0:port 作占位
            if self.remote is None:
                self.remote = addr
        parsed = _parse_rtp(data)
        if parsed is None:
            return
        pt, payload = parsed
        self.pkts_recv += 1
        self.bytes_recv += len(data)
        if not self.use_audio or self._out_stream is None:
            return
        try:
            pcm = g711.decode("pcma" if pt == PT_PCMA else "pcmu", payload)
            self._spk_buf.extend(pcm)
            # 限制缓冲，避免延迟无限堆积
            if len(self._spk_buf) > FRAME_BYTES_PCM16 * 20:
                del self._spk_buf[: len(self._spk_buf) - FRAME_BYTES_PCM16 * 10]
        except Exception as e:
            log.debug("decode err: %s", e)

    async def _sender_loop(self):
        silent_pcm = b"\x00" * FRAME_BYTES_PCM16
        next_t = time.monotonic()
        while not self._closed:
            next_t += FRAME_MS / 1000.0
            if self.use_audio:
                try:
                    pcm = self._mic_q.get_nowait()
                except asyncio.QueueEmpty:
                    pcm = silent_pcm
            else:
                pcm = silent_pcm
            if self.remote and self._transport:
                try:
                    payload = g711.encode(self.codec, pcm)
                    pkt = _build_rtp(self._seq, self._ts, self._ssrc, self.payload_type, payload)
                    self._transport.sendto(pkt, self.remote)
                    self.bytes_sent += len(pkt)
                    self.pkts_sent += 1
                except Exception as e:
                    log.debug("send err: %s", e)
            self._seq = (self._seq + 1) & 0xFFFF
            self._ts = (self._ts + FRAME_SAMPLES) & 0xFFFFFFFF
            sleep_s = next_t - time.monotonic()
            if sleep_s > 0:
                await asyncio.sleep(sleep_s)
            else:
                next_t = time.monotonic()  # 重新对齐

    async def stop(self):
        self._closed = True
        if self._send_task:
            self._send_task.cancel()
            try:
                await self._send_task
            except Exception:
                pass
        if self._in_stream is not None:
            try:
                self._in_stream.stop(); self._in_stream.close()
            except Exception:
                pass
        if self._out_stream is not None:
            try:
                self._out_stream.stop(); self._out_stream.close()
            except Exception:
                pass
        if self._transport:
            try:
                self._transport.close()
            except Exception:
                pass


__all__ = ["RtpSession", "FRAME_SAMPLES", "SAMPLE_RATE"]
