"""G.711 PCMU (µ-law) / PCMA (A-law) 编解码（纯 Python，无外部依赖）。

输入/输出说明：
  - linear16: signed 16-bit little-endian PCM bytes
  - ulaw / alaw: 1-byte-per-sample bytes
"""
from __future__ import annotations

import struct

# ---------------- µ-law (PCMU, payload type 0) ----------------

_BIAS = 0x84
_CLIP = 32635


def linear_to_ulaw(sample: int) -> int:
    sign = 0
    if sample < 0:
        sample = -sample
        sign = 0x80
    if sample > _CLIP:
        sample = _CLIP
    sample += _BIAS
    exponent = 7
    mask = 0x4000
    while exponent > 0 and not (sample & mask):
        exponent -= 1
        mask >>= 1
    mantissa = (sample >> (exponent + 3)) & 0x0F
    return (~(sign | (exponent << 4) | mantissa)) & 0xFF


def ulaw_to_linear(u: int) -> int:
    u = ~u & 0xFF
    sign = u & 0x80
    exponent = (u >> 4) & 0x07
    mantissa = u & 0x0F
    sample = ((mantissa << 3) + _BIAS) << exponent
    sample -= _BIAS
    return -sample if sign else sample


# ---------------- A-law (PCMA, payload type 8) ----------------

def linear_to_alaw(sample: int) -> int:
    sign = 0x00 if sample >= 0 else 0x80
    if sample < 0:
        sample = -sample
    if sample > 32635:
        sample = 32635
    if sample >= 256:
        exponent = 7
        mask = 0x4000
        while not (sample & mask):
            exponent -= 1
            mask >>= 1
        mantissa = (sample >> (exponent + 3)) & 0x0F
        a = (exponent << 4) | mantissa
    else:
        a = sample >> 4
    return (a | sign) ^ 0x55


def alaw_to_linear(a: int) -> int:
    a ^= 0x55
    sign = a & 0x80
    exponent = (a >> 4) & 0x07
    mantissa = a & 0x0F
    if exponent == 0:
        sample = (mantissa << 4) + 8
    else:
        sample = ((mantissa << 4) + 0x108) << (exponent - 1)
    return -sample if sign else sample


# ---------------- Bulk converters ----------------

def linear16_to_ulaw(pcm: bytes) -> bytes:
    n = len(pcm) // 2
    samples = struct.unpack(f"<{n}h", pcm)
    return bytes(linear_to_ulaw(s) for s in samples)


def ulaw_to_linear16(u: bytes) -> bytes:
    return struct.pack(f"<{len(u)}h", *(ulaw_to_linear(b) for b in u))


def linear16_to_alaw(pcm: bytes) -> bytes:
    n = len(pcm) // 2
    samples = struct.unpack(f"<{n}h", pcm)
    return bytes(linear_to_alaw(s) for s in samples)


def alaw_to_linear16(a: bytes) -> bytes:
    return struct.pack(f"<{len(a)}h", *(alaw_to_linear(b) for b in a))


def encode(codec: str, pcm: bytes) -> bytes:
    return linear16_to_alaw(pcm) if codec == "pcma" else linear16_to_ulaw(pcm)


def decode(codec: str, payload: bytes) -> bytes:
    return alaw_to_linear16(payload) if codec == "pcma" else ulaw_to_linear16(payload)
