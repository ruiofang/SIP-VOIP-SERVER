"""SIP/VoIP PC 测试客户端 (asyncio, 纯 Python)。

支持: REGISTER / MESSAGE / OPTIONS / INVITE / ACK / BYE / CANCEL,
G.711 PCMU/PCMA RTP 收发, REST 管理后台调用, 交互式 REPL + 脚本模式。
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import shlex
import socket
import sys
import time
import unicodedata
import uuid
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Dict, List, Optional, Tuple

try:
    from .rtp import RtpSession  # type: ignore
except ImportError:
    from rtp import RtpSession  # type: ignore


log = logging.getLogger("sipc")

# 交互式 REPL 是否启用：异步打印时在末尾重绘 "sip> " 提示符
_REPL_ACTIVE = False


def _async_print(text: str) -> None:
    """异步打印一段文本；若 REPL 处于交互模式，会清除当前提示行并在末尾重绘 ``sip> ``，
    同时把用户已经输入但尚未回车的 readline 缓冲区原样回显，避免输入丢失。"""
    line = text.rstrip("\n")
    if _REPL_ACTIVE:
        buf = ""
        try:
            import readline
            buf = readline.get_line_buffer()
        except Exception:
            pass
        # \r 回到行首, \033[K 清除到行尾, 打印消息后再重绘提示符 + 用户已输入内容
        sys.stdout.write("\r\033[K" + line + "\nsip> " + buf)
    else:
        sys.stdout.write(line + "\n")
    sys.stdout.flush()


def _safe_write_history(path: str) -> None:
    try:
        import readline
        readline.write_history_file(path)
    except Exception:
        pass


# =====================================================================
# SIP 报文
# =====================================================================

CRLF = b"\r\n"
EOL = "\r\n"


def md5_hex(s: str) -> str:
    return hashlib.md5(s.encode("utf-8")).hexdigest()


_URI_USER_RE = re.compile(r"sip:([^@>;\s]+)@", re.IGNORECASE)


def _extract_uri_user(value: str) -> Optional[str]:
    """从 From / To 头里提取 sip:user@host 中的 user。"""
    if not value:
        return None
    m = _URI_USER_RE.search(value)
    return m.group(1) if m else None


def _normalize_user_token(user: str) -> str:
    """统一用户标识格式，避免输入法空格/全角字符把 1002 变成 10。"""
    # NFKC: 全角数字/字母转半角；随后移除任意空白。
    v = unicodedata.normalize("NFKC", user or "")
    return "".join(v.split())


@dataclass
class SipMessage:
    is_request: bool
    method: str = ""
    request_uri: str = ""
    status_code: int = 0
    reason: str = ""
    headers: List[Tuple[str, str]] = field(default_factory=list)  # 保序
    body: bytes = b""

    # ----- 头部访问 -----
    def header(self, name: str) -> Optional[str]:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return None

    def header_all(self, name: str) -> List[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    def set(self, name: str, value: str):
        n = name.lower()
        for i, (k, _) in enumerate(self.headers):
            if k.lower() == n:
                self.headers[i] = (name, value)
                return
        self.headers.append((name, value))

    def append(self, name: str, value: str):
        self.headers.append((name, value))

    # ----- 序列化 -----
    def serialize(self) -> bytes:
        if self.is_request:
            start = f"{self.method} {self.request_uri} SIP/2.0"
        else:
            start = f"SIP/2.0 {self.status_code} {self.reason}"
        out = [start]
        # Content-Length 自动校正
        cl_set = False
        for i, (k, v) in enumerate(self.headers):
            if k.lower() == "content-length":
                self.headers[i] = (k, str(len(self.body)))
                cl_set = True
        if not cl_set:
            self.headers.append(("Content-Length", str(len(self.body))))
        for k, v in self.headers:
            out.append(f"{k}: {v}")
        return (EOL.join(out) + EOL + EOL).encode("utf-8") + self.body


def parse_sip(data: bytes) -> Optional[SipMessage]:
    try:
        head, _, body = data.partition(CRLF + CRLF)
        lines = head.decode("utf-8", errors="replace").split("\r\n")
        if not lines:
            return None
        first = lines[0]
        msg = SipMessage(is_request=False)
        if first.startswith("SIP/2.0"):
            parts = first.split(" ", 2)
            if len(parts) < 2:
                return None
            msg.is_request = False
            msg.status_code = int(parts[1])
            msg.reason = parts[2] if len(parts) > 2 else ""
        else:
            parts = first.split(" ", 2)
            if len(parts) < 3:
                return None
            msg.is_request = True
            msg.method = parts[0].upper()
            msg.request_uri = parts[1]
        for line in lines[1:]:
            if not line:
                continue
            k, _, v = line.partition(":")
            msg.headers.append((k.strip(), v.strip()))
        msg.body = body
        return msg
    except Exception as e:
        log.debug("parse_sip err: %s", e)
        return None


# =====================================================================
# SDP
# =====================================================================

def build_sdp(local_ip: str, rtp_port: int, codec: str = "pcmu") -> bytes:
    pt, name = (8, "PCMA/8000") if codec == "pcma" else (0, "PCMU/8000")
    sess_id = int(time.time())
    sdp = (
        f"v=0\r\n"
        f"o=- {sess_id} {sess_id} IN IP4 {local_ip}\r\n"
        f"s=sipc\r\n"
        f"c=IN IP4 {local_ip}\r\n"
        f"t=0 0\r\n"
        f"m=audio {rtp_port} RTP/AVP {pt} 101\r\n"
        f"a=rtpmap:{pt} {name}\r\n"
        f"a=rtpmap:101 telephone-event/8000\r\n"
        f"a=fmtp:101 0-16\r\n"
        f"a=ptime:20\r\n"
        f"a=sendrecv\r\n"
    )
    return sdp.encode("utf-8")


_C_RE = re.compile(rb"^c=IN IP4 (\S+)\s*$", re.MULTILINE)
_M_AUDIO_RE = re.compile(rb"^m=audio (\d+) ", re.MULTILINE)


def parse_sdp_audio(body: bytes) -> Optional[Tuple[str, int]]:
    cm = _C_RE.search(body)
    mm = _M_AUDIO_RE.search(body)
    if not cm or not mm:
        return None
    try:
        return cm.group(1).decode(), int(mm.group(1))
    except Exception:
        return None


def _is_private_or_special_ip(host: str) -> bool:
    """是否为私网/回环/链路本地/保留地址（NAT 场景常不可直达）。"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def _pick_rtp_remote(sdp_host: str, sdp_port: int, sig_addr: Optional[Tuple[str, int]]) -> Tuple[str, int]:
    """优先使用 SDP 地址；若 SDP 给的是私网而信令来源是公网，则回退到信令来源 IP。"""
    if not sig_addr:
        return sdp_host, sdp_port
    sig_host = sig_addr[0]
    if _is_private_or_special_ip(sdp_host) and not _is_private_or_special_ip(sig_host):
        return sig_host, sdp_port
    return sdp_host, sdp_port


# =====================================================================
# Digest
# =====================================================================

_DIGEST_RE = re.compile(r'(\w+)\s*=\s*(?:"([^"]*)"|([^,]+))')


def parse_digest_challenge(header_val: str) -> Dict[str, str]:
    if header_val.lower().startswith("digest"):
        header_val = header_val[6:]
    out: Dict[str, str] = {}
    for m in _DIGEST_RE.finditer(header_val):
        k = m.group(1).lower()
        out[k] = m.group(2) if m.group(2) is not None else m.group(3)
    return out


def build_digest_authorization(*, user: str, password: str, method: str, uri: str,
                               challenge: Dict[str, str], nc: int = 1) -> str:
    realm = challenge.get("realm", "")
    nonce = challenge.get("nonce", "")
    qop = challenge.get("qop", "")
    algorithm = challenge.get("algorithm", "MD5")
    opaque = challenge.get("opaque")
    ha1 = md5_hex(f"{user}:{realm}:{password}")
    ha2 = md5_hex(f"{method}:{uri}")
    cnonce = secrets.token_hex(8)
    nc_s = f"{nc:08x}"
    if "auth" in qop.lower():
        qop_v = "auth"
        response = md5_hex(f"{ha1}:{nonce}:{nc_s}:{cnonce}:{qop_v}:{ha2}")
    else:
        qop_v = ""
        response = md5_hex(f"{ha1}:{nonce}:{ha2}")
    parts = [
        f'username="{user}"', f'realm="{realm}"', f'nonce="{nonce}"',
        f'uri="{uri}"', f'response="{response}"', f"algorithm={algorithm}",
    ]
    if qop_v:
        parts += [f"qop={qop_v}", f"nc={nc_s}", f'cnonce="{cnonce}"']
    if opaque:
        parts.append(f'opaque="{opaque}"')
    return "Digest " + ", ".join(parts)


# =====================================================================
# SIP UA
# =====================================================================

@dataclass
class Dialog:
    call_id: str
    local_tag: str
    remote_tag: str = ""
    local_seq: int = 0
    remote_seq: int = 0
    local_uri: str = ""
    remote_uri: str = ""
    remote_target: str = ""  # 来自 Contact
    route_set: List[str] = field(default_factory=list)
    confirmed: bool = False
    is_caller: bool = True
    # 通话相关
    rtp: Optional[RtpSession] = None
    invite_branch: str = ""
    last_invite: Optional[SipMessage] = None  # 用于 ACK / 鉴权重发
    last_response: Optional[SipMessage] = None
    remote_addr: Tuple[str, int] = ("", 0)
    cancel_pending: bool = False


class _SipUdpProtocol(asyncio.DatagramProtocol):
    def __init__(self, on_dgram):
        self.on_dgram = on_dgram
        self.transport: Optional[asyncio.DatagramTransport] = None

    def connection_made(self, transport):
        self.transport = transport  # type: ignore

    def datagram_received(self, data, addr):
        self.on_dgram(data, addr)


class SipUA:
    def __init__(self, *, server_host: str, server_port: int, user: str, password: str,
                 realm: str, local_port: int = 0, rtp_port: int = 0,
                 codec: str = "pcmu", use_audio: bool = True,
                 auto_answer: bool = False, auto_read: bool = True,
                 local_ip_override: str = "", on_event=None):
        self.server_host = server_host
        self.server_port = server_port
        self.user = user
        self.password = password
        self.realm = realm
        self.local_port = local_port
        self.rtp_port = rtp_port
        self.codec = codec
        self.use_audio = use_audio
        self.auto_answer = auto_answer
        self.auto_read = auto_read
        self.local_ip_override = (local_ip_override or "").strip()
        self.on_event = on_event or (lambda *a, **kw: None)

        self.transport: Optional[asyncio.DatagramTransport] = None
        self.local_ip: str = "127.0.0.1"
        self.actual_local_port: int = 0
        self.cseq_counter: Dict[str, int] = {"REGISTER": 0, "MESSAGE": 0, "OPTIONS": 0, "INVITE": 0}
        self.registered = False
        self._refresh_task: Optional[asyncio.Task] = None
        self._stop = False
        # in-flight non-dialog transactions: branch -> future
        self._pending_tx: Dict[str, asyncio.Future] = {}
        self.dialogs: Dict[str, Dialog] = {}  # call-id -> Dialog
        self.active_call: Optional[str] = None  # call-id of current call
        self.incoming_invite: Optional[SipMessage] = None
        self.incoming_addr: Optional[Tuple[str, int]] = None
        self.incoming_rtp: Optional[RtpSession] = None

    async def _warn_if_no_rtp(self, call_id: str, delay: float = 3.0) -> None:
        await asyncio.sleep(delay)
        d = self.dialogs.get(call_id)
        if not d or not d.rtp or d.rtp.pkts_recv > 0:
            return
        remote = f"{d.rtp.remote[0]}:{d.rtp.remote[1]}" if d.rtp.remote else "<unknown>"
        hints = [
            f"[RTP] 通话建立后 {int(delay)}s 仍未收到媒体包；当前远端={remote}",
            "[RTP] 可先输入 status 查看 pkts_sent/pkts_recv；若 sent 持续增长而 recv 为 0，优先检查本机 UDP/防火墙/安全组。",
        ]
        if self.local_ip_override:
            hints.append(f"[RTP] 当前已强制本端地址 --local-ip {self.local_ip_override}")
        else:
            hints.append("[RTP] 若处于多网卡、VPN 或直连媒体场景，可尝试用 --local-ip 指定可达的本机地址。")
        for line in hints:
            _async_print(line)

    # ---- 启动 ----
    async def start(self):
        loop = asyncio.get_running_loop()
        # 探测出口 IP（可用 --local-ip 强制覆盖，适配多网卡/VPN 场景）
        if self.local_ip_override:
            self.local_ip = self.local_ip_override
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect((self.server_host, self.server_port))
                    self.local_ip = s.getsockname()[0]
            except Exception:
                self.local_ip = "127.0.0.1"
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: _SipUdpProtocol(self._on_dgram),
            local_addr=("0.0.0.0", self.local_port),
        )
        sock = self.transport.get_extra_info("socket")
        self.actual_local_port = sock.getsockname()[1]
        log.info("SIP listening on %s:%s (local_ip=%s)", "0.0.0.0", self.actual_local_port, self.local_ip)

    async def stop(self):
        self._stop = True
        if self._refresh_task:
            self._refresh_task.cancel()
        # 关闭活跃通话
        for d in list(self.dialogs.values()):
            if d.rtp:
                await d.rtp.stop()
        if self.transport:
            self.transport.close()

    # ---- 通用 ----
    def _send(self, msg: SipMessage, addr: Optional[Tuple[str, int]] = None):
        addr = addr or (self.server_host, self.server_port)
        data = msg.serialize()
        assert self.transport
        self.transport.sendto(data, addr)
        if log.isEnabledFor(logging.DEBUG):
            log.debug(">>> %s\n%s", addr, data.decode("utf-8", "replace"))

    def _next_cseq(self, method: str) -> int:
        self.cseq_counter[method] = self.cseq_counter.get(method, 0) + 1
        return self.cseq_counter[method]

    def _new_branch(self) -> str:
        return "z9hG4bK" + secrets.token_hex(6)

    def _new_callid(self) -> str:
        return f"{secrets.token_hex(8)}@{self.local_ip}"

    def _new_tag(self) -> str:
        return secrets.token_hex(4)

    def _via(self, branch: str) -> str:
        return f"SIP/2.0/UDP {self.local_ip}:{self.actual_local_port};branch={branch};rport"

    def _contact(self) -> str:
        return f"<sip:{self.user}@{self.local_ip}:{self.actual_local_port}>"

    def _aor(self) -> str:
        return f"sip:{self.user}@{self.realm}"

    # ---- 入口 ----
    def _on_dgram(self, data: bytes, addr: Tuple[str, int]):
        if log.isEnabledFor(logging.DEBUG):
            log.debug("<<< %s\n%s", addr, data.decode("utf-8", "replace"))
        msg = parse_sip(data)
        if not msg:
            return
        if msg.is_request:
            asyncio.create_task(self._on_request(msg, addr))
        else:
            self._on_response(msg, addr)

    # ---- 响应路由 ----
    def _on_response(self, msg: SipMessage, addr):
        via_top = msg.header("Via") or ""
        bm = re.search(r"branch=([^;,\s]+)", via_top)
        branch = bm.group(1) if bm else ""
        cseq = msg.header("CSeq") or ""
        method = cseq.split()[-1].upper() if cseq else ""
        callid = msg.header("Call-ID") or ""
        # 非 INVITE 事务 (Register/Message/Options): future
        if branch in self._pending_tx:
            fut = self._pending_tx[branch]
            if msg.status_code >= 200:  # 终态
                self._pending_tx.pop(branch, None)
                if not fut.done():
                    fut.set_result(msg)
            else:
                # 1xx 临时, 忽略
                return
            return
        # INVITE 事务: 路由到 dialog
        if method == "INVITE" and callid in self.dialogs:
            asyncio.create_task(self._on_invite_response(self.dialogs[callid], msg, addr))
            return
        if method == "BYE" and callid in self.dialogs:
            # 终结
            return
        log.debug("未匹配的响应 branch=%s method=%s callid=%s status=%s",
                  branch, method, callid, msg.status_code)

    # ---- 请求处理 ----
    async def _on_request(self, msg: SipMessage, addr):
        method = msg.method
        if method == "OPTIONS":
            self._send(self._build_response(msg, 200, "OK"), addr)
        elif method == "MESSAGE":
            ct = msg.header("Content-Type") or "text/plain"
            ctl = ct.lower()
            frm = msg.header("From") or ""
            from_user = _extract_uri_user(frm) or frm
            srv_msg_id = msg.header("X-Message-ID")
            # ---- 状态回执（服务端推送的“已送达 / 已读”） ----
            if "application/x-message-status" in ctl:
                self._send(self._build_response(msg, 200, "OK"), addr)
                try:
                    payload = json.loads(msg.body.decode("utf-8", "replace"))
                except Exception:
                    payload = {}
                mid = payload.get("msg_id")
                status = payload.get("status")
                target = payload.get("to") or from_user
                self.on_event("message_status", {
                    "msg_id": mid, "status": status, "to": target,
                })
                label = {"delivered": "已送达", "read": "已读",
                         "failed": "投递失败"}.get(str(status), str(status))
                _async_print(f"[STATUS msg #{mid} -> {target}] {label}")
                return
            # ---- 普通消息 ----
            text = msg.body.decode("utf-8", "replace") if "text" in ctl else f"<{len(msg.body)} bytes {ct}>"
            self.on_event("message", {"from": frm, "from_user": from_user,
                                      "content_type": ct, "text": text,
                                      "raw": msg.body, "msg_id": srv_msg_id})
            tag = f" #{srv_msg_id}" if srv_msg_id else ""
            _async_print(f"[MSG{tag} from {from_user}] {text}")
            self._send(self._build_response(msg, 200, "OK"), addr)
            # 自动已读回执
            if srv_msg_id and self.auto_read and from_user:
                asyncio.create_task(self._send_read_receipt(from_user, srv_msg_id))
        elif method == "INVITE":
            await self._on_incoming_invite(msg, addr)
        elif method == "ACK":
            callid = msg.header("Call-ID") or ""
            d = self.dialogs.get(callid)
            if d:
                d.confirmed = True
        elif method == "BYE":
            callid = msg.header("Call-ID") or ""
            d = self.dialogs.get(callid)
            if d:
                self._send(self._build_response(msg, 200, "OK"), addr)
                await self._teardown_dialog(d, reason="对端挂断")
            else:
                self._send(self._build_response(msg, 481, "Call/Transaction Does Not Exist"), addr)
        elif method == "CANCEL":
            callid = msg.header("Call-ID") or ""
            d = self.dialogs.get(callid)
            self._send(self._build_response(msg, 200, "OK"), addr)
            if d and not d.confirmed:
                # 回送 487 给原 INVITE
                if self.incoming_invite and (self.incoming_invite.header("Call-ID") or "") == callid:
                    self._send(self._build_response(self.incoming_invite, 487, "Request Terminated"), addr)
                await self._teardown_dialog(d, reason="对端取消")
        elif method == "NOTIFY":
            self._send(self._build_response(msg, 200, "OK"), addr)
        else:
            self._send(self._build_response(msg, 200, "OK"), addr)

    def _build_response(self, req: SipMessage, code: int, reason: str,
                        extra_headers: Optional[Dict[str, str]] = None,
                        body: bytes = b"", content_type: str = "") -> SipMessage:
        r = SipMessage(is_request=False, status_code=code, reason=reason)
        for k, v in req.headers:
            kl = k.lower()
            if kl in ("via", "from", "to", "call-id", "cseq", "record-route"):
                r.headers.append((k, v))
        # To 添加 tag（如未带）
        for i, (k, v) in enumerate(r.headers):
            if k.lower() == "to" and ";tag=" not in v:
                r.headers[i] = (k, v + f";tag={self._new_tag()}")
        if extra_headers:
            for k, v in extra_headers.items():
                r.headers.append((k, v))
        if body:
            r.headers.append(("Content-Type", content_type or "application/sdp"))
        r.body = body
        return r

    # ====================== REGISTER ======================
    async def register(self, expires: int = 600, retries: int = 1) -> bool:
        nc = 0
        last_chal: Optional[Dict[str, str]] = None
        for attempt in range(retries + 2):
            nc += 1
            cseq = self._next_cseq("REGISTER")
            branch = self._new_branch()
            tag = self._new_tag() if attempt == 0 else None
            uri = f"sip:{self.realm}"
            req = SipMessage(is_request=True, method="REGISTER", request_uri=uri)
            req.headers = [
                ("Via", self._via(branch)),
                ("Max-Forwards", "70"),
                ("From", f'<{self._aor()}>;tag={tag or self._new_tag()}'),
                ("To", f'<{self._aor()}>'),
                ("Call-ID", self._new_callid()),
                ("CSeq", f"{cseq} REGISTER"),
                ("Contact", f'{self._contact()};expires={expires}'),
                ("Expires", str(expires)),
                ("User-Agent", "sipc-py/1.0"),
            ]
            if last_chal:
                req.headers.append((
                    "Authorization",
                    build_digest_authorization(user=self.user, password=self.password,
                                               method="REGISTER", uri=uri,
                                               challenge=last_chal, nc=nc),
                ))
            resp = await self._tx_send(req, branch)
            if resp is None:
                log.error("REGISTER 超时")
                return False
            if resp.status_code in (401, 407):
                hdr = resp.header("WWW-Authenticate") or resp.header("Proxy-Authenticate") or ""
                last_chal = parse_digest_challenge(hdr)
                continue
            if 200 <= resp.status_code < 300:
                self.registered = expires > 0
                self.on_event("registered", {"expires": expires})
                if expires > 0 and not self._refresh_task:
                    self._refresh_task = asyncio.create_task(self._refresh_loop(expires))
                return True
            log.error("REGISTER 失败: %s %s", resp.status_code, resp.reason)
            return False
        return False

    async def _refresh_loop(self, expires: int):
        while not self._stop and self.registered:
            await asyncio.sleep(max(60, expires - 30))
            if self._stop:
                break
            try:
                await self.register(expires=expires)
            except Exception as e:
                log.warning("注册刷新失败: %s", e)

    async def unregister(self):
        if not self.registered:
            return
        await self.register(expires=0)
        self.registered = False

    # ====================== MESSAGE ======================
    async def send_message(self, to_user: str, text: str,
                           content_type: str = "text/plain;charset=UTF-8"
                           ) -> Tuple[bool, Optional[str]]:
        """发送 SIP MESSAGE。返回 (是否 2xx, 服务端分配的 X-Message-ID)。"""
        to_user = _normalize_user_token(to_user)
        if not to_user:
            return False, None
        nc = 0
        last_chal = None
        body = text.encode("utf-8")
        callid = self._new_callid()
        ftag = self._new_tag()
        for _ in range(3):
            nc += 1
            cseq = self._next_cseq("MESSAGE")
            branch = self._new_branch()
            uri = f"sip:{to_user}@{self.realm}"
            req = SipMessage(is_request=True, method="MESSAGE", request_uri=uri)
            req.headers = [
                ("Via", self._via(branch)),
                ("Max-Forwards", "70"),
                ("From", f'<{self._aor()}>;tag={ftag}'),
                ("To", f'<{uri}>'),
                ("Call-ID", callid),
                ("CSeq", f"{cseq} MESSAGE"),
                ("Contact", self._contact()),
                ("User-Agent", "sipc-py/1.0"),
                ("Content-Type", content_type),
            ]
            if last_chal:
                req.headers.append((
                    "Authorization",
                    build_digest_authorization(user=self.user, password=self.password,
                                               method="MESSAGE", uri=uri,
                                               challenge=last_chal, nc=nc),
                ))
            req.body = body
            resp = await self._tx_send(req, branch)
            if resp is None:
                return False, None
            if resp.status_code in (401, 407):
                hdr = resp.header("WWW-Authenticate") or resp.header("Proxy-Authenticate") or ""
                last_chal = parse_digest_challenge(hdr)
                continue
            ok = 200 <= resp.status_code < 300
            mid = resp.header("X-Message-ID") if ok else None
            return ok, mid
        return False, None

    async def _send_read_receipt(self, to_user: str, msg_id: str) -> None:
        """收到服务端推送的消息后，自动回送 read 回执。"""
        try:
            payload = json.dumps({"msg_id": int(msg_id), "status": "read"})
        except Exception:
            return
        try:
            await self.send_message(to_user, payload,
                                    content_type="application/x-message-status+json")
        except Exception as e:
            log.debug("send read receipt failed: %s", e)

    async def mark_read(self, to_user: str, msg_id: str) -> bool:
        """显式发送 read 回执（REPL `read <to_user> <msg_id>`）。"""
        ok, _ = await self.send_message(
            to_user, json.dumps({"msg_id": int(msg_id), "status": "read"}),
            content_type="application/x-message-status+json",
        )
        return ok

    async def options_ping(self) -> Optional[int]:
        cseq = self._next_cseq("OPTIONS")
        branch = self._new_branch()
        uri = f"sip:{self.realm}"
        req = SipMessage(is_request=True, method="OPTIONS", request_uri=uri)
        req.headers = [
            ("Via", self._via(branch)),
            ("Max-Forwards", "70"),
            ("From", f'<{self._aor()}>;tag={self._new_tag()}'),
            ("To", f'<{uri}>'),
            ("Call-ID", self._new_callid()),
            ("CSeq", f"{cseq} OPTIONS"),
            ("Contact", self._contact()),
            ("User-Agent", "sipc-py/1.0"),
        ]
        resp = await self._tx_send(req, branch)
        return resp.status_code if resp else None

    # ====================== 通用事务发送 ======================
    async def _tx_send(self, req: SipMessage, branch: str, timeout: float = 32.0) -> Optional[SipMessage]:
        loop = asyncio.get_running_loop()
        fut: asyncio.Future = loop.create_future()
        self._pending_tx[branch] = fut
        # 简单重传: T1=500ms, exp backoff, 最多 ~6 次
        async def retransmit():
            interval = 0.5
            elapsed = 0.0
            while not fut.done() and elapsed < timeout:
                self._send(req)
                await asyncio.sleep(interval)
                elapsed += interval
                interval = min(interval * 2, 4.0)
        rtask = asyncio.create_task(retransmit())
        try:
            return await asyncio.wait_for(fut, timeout=timeout)
        except asyncio.TimeoutError:
            self._pending_tx.pop(branch, None)
            return None
        finally:
            rtask.cancel()

    # ====================== INVITE (主叫) ======================
    async def call(self, to_user: str) -> bool:
        to_user = _normalize_user_token(to_user)
        if not to_user:
            print("目标账号不能为空")
            return False
        if self.active_call:
            print("已有活跃通话，先 hangup")
            return False
        callid = self._new_callid()
        ftag = self._new_tag()
        # 准备 RTP
        rtp = RtpSession(local_port=self.rtp_port, codec=self.codec, use_audio=self.use_audio)
        await rtp.start()
        d = Dialog(call_id=callid, local_tag=ftag, is_caller=True,
                   local_uri=self._aor(),
                   remote_uri=f"sip:{to_user}@{self.realm}",
                   remote_target=f"sip:{to_user}@{self.realm}",
                   rtp=rtp)
        self.dialogs[callid] = d
        self.active_call = callid

        sdp = build_sdp(self.local_ip, rtp.actual_local_port, codec=self.codec)
        sent = await self._send_invite(d, sdp, auth_chal=None)
        if not sent:
            await self._teardown_dialog(d, reason="发送 INVITE 失败")
            return False
        return True

    async def _send_invite(self, d: Dialog, sdp: bytes, auth_chal: Optional[Dict[str, str]],
                           nc: int = 1) -> bool:
        cseq = self._next_cseq("INVITE")
        branch = self._new_branch()
        d.invite_branch = branch
        uri = d.remote_uri
        req = SipMessage(is_request=True, method="INVITE", request_uri=uri)
        req.headers = [
            ("Via", self._via(branch)),
            ("Max-Forwards", "70"),
            ("From", f'<{d.local_uri}>;tag={d.local_tag}'),
            ("To", f'<{d.remote_uri}>'),
            ("Call-ID", d.call_id),
            ("CSeq", f"{cseq} INVITE"),
            ("Contact", self._contact()),
            ("Allow", "INVITE,ACK,CANCEL,BYE,OPTIONS,MESSAGE,NOTIFY"),
            ("User-Agent", "sipc-py/1.0"),
            ("Content-Type", "application/sdp"),
        ]
        if auth_chal:
            req.headers.append((
                "Authorization",
                build_digest_authorization(user=self.user, password=self.password,
                                           method="INVITE", uri=uri,
                                           challenge=auth_chal, nc=nc),
            ))
        req.body = sdp
        d.last_invite = req
        d.local_seq = cseq
        try:
            self._send(req)
            return True
        except Exception as e:
            log.error("send INVITE err: %s", e)
            return False

    async def _on_invite_response(self, d: Dialog, msg: SipMessage, addr):
        d.last_response = msg
        code = msg.status_code
        # To tag
        to_h = msg.header("To") or ""
        m = re.search(r"tag=([^;,\s]+)", to_h)
        if m:
            d.remote_tag = m.group(1)
        if 100 <= code < 200:
            print(f"[CALL] {code} {msg.reason}", flush=True)
            self.on_event("call_progress", {"code": code, "reason": msg.reason})
            return
        if code in (401, 407):
            hdr = msg.header("WWW-Authenticate") or msg.header("Proxy-Authenticate") or ""
            chal = parse_digest_challenge(hdr)
            # ACK 401 (in-Via) — 实际上对 401 INVITE 必须 ACK
            self._send_ack_for_failure(d, msg, addr)
            # 重新发起 INVITE，新 branch，新 callid 不变？  RFC 推荐换 callid? 我们换 callid 简化
            sdp = build_sdp(self.local_ip, d.rtp.actual_local_port if d.rtp else 0, codec=self.codec)
            d.local_tag = self._new_tag()
            await self._send_invite(d, sdp, auth_chal=chal, nc=2)
            return
        if 200 <= code < 300:
            # 解析 SDP -> 设定 RTP 远端
            ct = msg.header("Content-Type") or ""
            if "sdp" in ct.lower():
                au = parse_sdp_audio(msg.body)
                if au and d.rtp:
                    remote_host, remote_port = _pick_rtp_remote(au[0], au[1], addr)
                    if (remote_host, remote_port) != au:
                        log.warning(
                            "RTP SDP地址 %s:%s 可能不可达，回退为信令源 %s:%s",
                            au[0], au[1], remote_host, remote_port,
                        )
                    d.rtp.set_remote(remote_host, remote_port)
            # Contact 作为后续目标
            ctc = msg.header("Contact") or ""
            cm = re.search(r"<([^>]+)>", ctc)
            if cm:
                d.remote_target = cm.group(1)
            # Record-Route
            d.route_set = list(reversed(msg.header_all("Record-Route")))
            # 发 ACK
            self._send_ack_in_dialog(d)
            d.confirmed = True
            print(f"[CALL] 200 OK 通话已建立", flush=True)
            self.on_event("call_established", {"call_id": d.call_id})
            asyncio.create_task(self._warn_if_no_rtp(d.call_id))
            return
        # 失败
        self._send_ack_for_failure(d, msg, addr)
        print(f"[CALL] 失败 {code} {msg.reason}", flush=True)
        self.on_event("call_failed", {"code": code, "reason": msg.reason})
        await self._teardown_dialog(d, reason=f"{code} {msg.reason}")

    def _send_ack_for_failure(self, d: Dialog, resp: SipMessage, addr):
        # ACK 走原始事务 (同 branch, no To-tag from response 但实际包含 remote tag)
        ack = SipMessage(is_request=True, method="ACK", request_uri=d.remote_uri)
        ack.headers = [
            ("Via", self._via(d.invite_branch)),
            ("Max-Forwards", "70"),
            ("From", f'<{d.local_uri}>;tag={d.local_tag}'),
            ("To", resp.header("To") or f"<{d.remote_uri}>"),
            ("Call-ID", d.call_id),
            ("CSeq", f"{d.local_seq} ACK"),
            ("User-Agent", "sipc-py/1.0"),
        ]
        self._send(ack)

    def _send_ack_in_dialog(self, d: Dialog):
        ack = SipMessage(is_request=True, method="ACK", request_uri=d.remote_target)
        branch = self._new_branch()
        ack.headers = [
            ("Via", self._via(branch)),
            ("Max-Forwards", "70"),
            ("From", f'<{d.local_uri}>;tag={d.local_tag}'),
            ("To", f'<{d.remote_uri}>;tag={d.remote_tag}' if d.remote_tag else f'<{d.remote_uri}>'),
            ("Call-ID", d.call_id),
            ("CSeq", f"{d.local_seq} ACK"),
            ("User-Agent", "sipc-py/1.0"),
        ]
        for r in d.route_set:
            ack.headers.append(("Route", r))
        self._send(ack)

    # ====================== 来电 ======================
    async def _on_incoming_invite(self, msg: SipMessage, addr):
        callid = msg.header("Call-ID") or ""
        # 已有同 dialog → re-INVITE：直接 200 OK 复用现有 SDP
        if callid in self.dialogs and self.dialogs[callid].confirmed:
            d = self.dialogs[callid]
            sdp = build_sdp(self.local_ip, d.rtp.actual_local_port if d.rtp else 0, codec=self.codec)
            self._send(self._build_response(msg, 200, "OK", body=sdp, content_type="application/sdp"), addr)
            return
        # 已有活跃通话 -> 486 Busy
        if self.active_call:
            self._send(self._build_response(msg, 486, "Busy Here"), addr)
            return
        self.incoming_invite = msg
        self.incoming_addr = addr
        # 100 Trying
        self._send(self._build_response(msg, 100, "Trying"), addr)
        # 180 Ringing
        self._send(self._build_response(msg, 180, "Ringing"), addr)
        frm = msg.header("From") or ""
        _async_print(f"[INCOMING CALL] from {frm}  -> 输入 answer / reject")
        self.on_event("incoming_call", {"from": frm, "call_id": callid})
        if self.auto_answer:
            await asyncio.sleep(0.3)
            await self.answer()

    async def answer(self) -> bool:
        if not self.incoming_invite:
            print("没有来电")
            return False
        msg = self.incoming_invite
        addr = self.incoming_addr
        callid = msg.header("Call-ID") or ""
        ftag = msg.header("From") or ""
        ttag_local = self._new_tag()
        # 启动 RTP
        rtp = RtpSession(local_port=self.rtp_port, codec=self.codec, use_audio=self.use_audio)
        await rtp.start()
        # 解析对端 SDP
        au = parse_sdp_audio(msg.body) if msg.body else None
        if au:
            remote_host, remote_port = _pick_rtp_remote(au[0], au[1], addr)
            if (remote_host, remote_port) != au:
                log.warning(
                    "RTP SDP地址 %s:%s 可能不可达，回退为信令源 %s:%s",
                    au[0], au[1], remote_host, remote_port,
                )
            rtp.set_remote(remote_host, remote_port)
        # 构造 dialog
        m = re.search(r"tag=([^;,\s]+)", ftag)
        remote_tag = m.group(1) if m else ""
        from_uri_m = re.search(r"<([^>]+)>", ftag)
        remote_uri = from_uri_m.group(1) if from_uri_m else ""
        cseq_h = msg.header("CSeq") or "0 INVITE"
        try:
            remote_cseq = int(cseq_h.split()[0])
        except Exception:
            remote_cseq = 0
        contact = msg.header("Contact") or ""
        cm = re.search(r"<([^>]+)>", contact)
        remote_target = cm.group(1) if cm else remote_uri
        d = Dialog(call_id=callid, local_tag=ttag_local, remote_tag=remote_tag,
                   local_uri=self._aor(), remote_uri=remote_uri,
                   remote_target=remote_target,
                   remote_seq=remote_cseq, is_caller=False, rtp=rtp,
                   remote_addr=addr or ("", 0))
        self.dialogs[callid] = d
        self.active_call = callid
        sdp = build_sdp(self.local_ip, rtp.actual_local_port, codec=self.codec)
        # 200 OK 必须带 To-tag
        ok = self._build_response(msg, 200, "OK", body=sdp, content_type="application/sdp")
        # 替换 To 让它使用我们指定的 tag
        for i, (k, v) in enumerate(ok.headers):
            if k.lower() == "to":
                # 去掉自动加的 tag
                base = re.sub(r";tag=[^;,\s]+", "", v)
                ok.headers[i] = (k, base + f";tag={ttag_local}")
                break
        ok.append("Contact", self._contact())
        self._send(ok, addr)
        self.incoming_invite = None
        self.incoming_addr = None
        print("[CALL] 已接听", flush=True)
        self.on_event("call_established", {"call_id": callid})
        asyncio.create_task(self._warn_if_no_rtp(callid))
        return True

    async def reject(self, code: int = 603, reason: str = "Decline") -> bool:
        if not self.incoming_invite:
            print("没有来电")
            return False
        self._send(self._build_response(self.incoming_invite, code, reason), self.incoming_addr)
        self.incoming_invite = None
        self.incoming_addr = None
        return True

    # ====================== BYE / CANCEL ======================
    async def hangup(self) -> bool:
        if not self.active_call:
            print("无活跃通话")
            return False
        d = self.dialogs.get(self.active_call)
        if not d:
            return False
        if d.is_caller and not d.confirmed:
            # 未建立完成 -> CANCEL
            await self._send_cancel(d)
        else:
            await self._send_bye(d)
        await self._teardown_dialog(d, reason="本端挂断")
        return True

    async def _send_bye(self, d: Dialog):
        cseq = (d.local_seq or 1) + 1
        d.local_seq = cseq
        branch = self._new_branch()
        bye = SipMessage(is_request=True, method="BYE", request_uri=d.remote_target)
        bye.headers = [
            ("Via", self._via(branch)),
            ("Max-Forwards", "70"),
            ("From", f'<{d.local_uri}>;tag={d.local_tag}'),
            ("To", f'<{d.remote_uri}>;tag={d.remote_tag}' if d.remote_tag else f'<{d.remote_uri}>'),
            ("Call-ID", d.call_id),
            ("CSeq", f"{cseq} BYE"),
            ("User-Agent", "sipc-py/1.0"),
        ]
        for r in d.route_set:
            bye.headers.append(("Route", r))
        self._send(bye)

    async def _send_cancel(self, d: Dialog):
        if not d.last_invite:
            return
        cancel = SipMessage(is_request=True, method="CANCEL", request_uri=d.last_invite.request_uri)
        # CANCEL 必须复用 INVITE 的 Via, Call-ID, From, CSeq-num, To(无 tag)
        cancel.headers = [
            ("Via", d.last_invite.header("Via") or self._via(d.invite_branch)),
            ("Max-Forwards", "70"),
            ("From", d.last_invite.header("From") or ""),
            ("To", d.last_invite.header("To") or ""),
            ("Call-ID", d.call_id),
            ("CSeq", f"{d.local_seq} CANCEL"),
            ("User-Agent", "sipc-py/1.0"),
        ]
        self._send(cancel)

    async def _teardown_dialog(self, d: Dialog, reason: str = ""):
        if d.rtp:
            try:
                await d.rtp.stop()
            except Exception:
                pass
            d.rtp = None
        self.dialogs.pop(d.call_id, None)
        if self.active_call == d.call_id:
            self.active_call = None
        print(f"[CALL] 结束 ({reason})", flush=True)
        self.on_event("call_ended", {"call_id": d.call_id, "reason": reason})


# =====================================================================
# REST 管理后台
# =====================================================================

class AdminAPI:
    def __init__(self, base: str, user: str, password: str):
        self.base = base.rstrip("/")
        self.user = user
        self.password = password
        self.token: Optional[str] = None
        try:
            import requests  # noqa
            self._requests = requests
        except ImportError:
            self._requests = None

    def _ok(self) -> bool:
        return self._requests is not None and bool(self.base)

    def login(self) -> bool:
        if not self._ok():
            return False
        try:
            r = self._requests.post(
                f"{self.base}/api/auth/login",
                data={"username": self.user, "password": self.password}, timeout=8,
            )
            r.raise_for_status()
            self.token = r.json().get("access_token")
            return self.token is not None
        except Exception as e:
            log.warning("admin login failed: %s", e)
            return False

    def _h(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _ensure(self):
        if not self.token:
            self.login()

    def list_accounts(self):
        self._ensure()
        r = self._requests.get(f"{self.base}/api/accounts", headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()

    def list_calls(self):
        self._ensure()
        r = self._requests.get(f"{self.base}/api/calls", headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()

    def list_messages(self, user: Optional[str] = None):
        self._ensure()
        params = {"user": user} if user else {}
        r = self._requests.get(f"{self.base}/api/messages", headers=self._h(),
                               params=params, timeout=8)
        r.raise_for_status(); return r.json()

    def send_message_via_api(self, to_user: str, text: str):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/send_message", headers=self._h(),
                                json={"to_user": to_user, "text": text}, timeout=8)
        r.raise_for_status(); return r.json()

    def upload_voice(self, path: str, to_user: Optional[str] = None):
        self._ensure()
        with open(path, "rb") as f:
            files = {"file": (os.path.basename(path), f, "application/octet-stream")}
            data = {"to_user": to_user} if to_user else {}
            r = self._requests.post(f"{self.base}/api/voice/upload", headers=self._h(),
                                    files=files, data=data, timeout=60)
        r.raise_for_status(); return r.json()

    def hangup_call(self, call_id: str):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/calls/{call_id}/hangup",
                                headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()


class UserAPI:
    """SIP 用户自助 API：好友、扫码加好友等。

    用 SIP 账号自身密码登录 /api/user/login 获取 user-kind JWT。
    """

    def __init__(self, base: str, sip_user: str, sip_password: str):
        self.base = base.rstrip("/")
        self.user = sip_user
        self.password = sip_password
        self.token: Optional[str] = None
        try:
            import requests  # noqa
            self._requests = requests
        except ImportError:
            self._requests = None

    def _ok(self) -> bool:
        return self._requests is not None and bool(self.base)

    def login(self) -> bool:
        if not self._ok():
            return False
        try:
            r = self._requests.post(
                f"{self.base}/api/user/login",
                data={"username": self.user, "password": self.password}, timeout=8,
            )
            r.raise_for_status()
            self.token = r.json().get("access_token")
            return self.token is not None
        except Exception as e:
            log.warning("user login failed: %s", e)
            return False

    def _h(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _ensure(self):
        if not self.token:
            self.login()

    def list_friends(self):
        self._ensure()
        r = self._requests.get(f"{self.base}/api/friends", headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()

    def request_friend(self, to_user: str, note: Optional[str] = None):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/friends/request",
                                headers=self._h(),
                                json={"to_user": to_user, "note": note}, timeout=8)
        r.raise_for_status(); return r.json()

    def accept_friend(self, fid: int):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/friends/{fid}/accept",
                                headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()

    def reject_friend(self, fid: int):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/friends/{fid}/reject",
                                headers=self._h(), timeout=8)
        r.raise_for_status(); return {"ok": True}

    def delete_friend(self, fid: int):
        self._ensure()
        r = self._requests.delete(f"{self.base}/api/friends/{fid}",
                                  headers=self._h(), timeout=8)
        r.raise_for_status(); return {"ok": True}

    def create_invite(self, ttl: int = 600, note: Optional[str] = None):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/friends/invite",
                                headers=self._h(),
                                json={"ttl_seconds": ttl, "note": note}, timeout=8)
        r.raise_for_status(); return r.json()

    def list_invites(self):
        self._ensure()
        r = self._requests.get(f"{self.base}/api/friends/invites",
                               headers=self._h(), timeout=8)
        r.raise_for_status(); return r.json()

    def scan_invite(self, token: str, note: Optional[str] = None):
        self._ensure()
        r = self._requests.post(f"{self.base}/api/friends/scan",
                                headers=self._h(),
                                json={"token": token, "note": note}, timeout=8)
        r.raise_for_status(); return r.json()


def render_qr(payload: str) -> str:
    """渲染 ASCII QR；若 `qrcode` 库不可用则返回提示串。"""
    try:
        import qrcode  # type: ignore
    except ImportError:
        return ("[未安装 qrcode 包，无法渲染 QR；可执行: pip install qrcode]\n"
                f"原始 payload: {payload}")
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=1)
    qr.add_data(payload)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    # 用半块字符压缩 2 行 → 1 行
    rows = []
    for y in range(0, len(matrix), 2):
        line = []
        upper = matrix[y]
        lower = matrix[y + 1] if y + 1 < len(matrix) else [False] * len(upper)
        for u, l in zip(upper, lower):
            if u and l:
                line.append("█")
            elif u:
                line.append("▀")
            elif l:
                line.append("▄")
            else:
                line.append(" ")
        rows.append("".join(line))
    return "\n".join(rows)


# =====================================================================
# REPL
# =====================================================================

HELP = """
可用命令:
  register            注册到服务器（默认启动时已注册）
  unregister          注销
  options             OPTIONS ping
  msg <user> <text..> 发送文本短信
  read <user> <msgid> 手动给某条消息发送已读回执
  call <user>         拨打
  answer              接听来电
  reject              拒接来电
  hangup              挂断当前通话
  status              本机状态

  ---- 好友（用 SIP 账号登录 /api/user）----
  friends                列出我的好友 + pending 请求
  friend-add <user> [note]   发送好友申请（pending）
  friend-accept <id>     通过好友申请
  friend-reject <id>     拒绝好友申请
  friend-del <id>        删除/取消好友
  qr [ttl] [note]        生成扫码邀请并打印二维码
  invites                列出我已发出的邀请
  scan <token> [note]    用别人的邀请 token 加为好友
  scan-uri <sipfriend://...>  从扫描得到的 URI 直接加好友

  ---- 管理后台（admin 凭据）----
  who                 列出账号
  calls               实时通话
  hist [user]         消息历史
  upload <path> [to]  上传语音并推送
  api-msg <u> <text>  REST 发消息
  rest-hangup <id>    REST 强制挂断

  sleep <sec>         脚本中等待
  set audio on|off    切换音频
  help / quit / exit
""".strip()


async def repl(ua: SipUA, api: AdminAPI, user_api: UserAPI,
               script_lines: Optional[List[str]] = None):
    global _REPL_ACTIVE
    if script_lines is None:
        _REPL_ACTIVE = True
        # 启用 readline：支持方向键光标移动 / 历史 / Backspace 等行编辑
        try:
            import readline  # noqa: F401  (Linux/macOS 自带)
            import atexit
            hist_path = os.path.expanduser("~/.sip_client_history")
            try:
                readline.read_history_file(hist_path)
            except (FileNotFoundError, OSError):
                pass
            readline.set_history_length(1000)
            atexit.register(lambda: _safe_write_history(hist_path))
        except ImportError:
            pass
        # 异步读 stdin：用 daemon 线程，避免 Ctrl+C 后 atexit 卡在 join 上
        import threading
        loop = asyncio.get_running_loop()
        async def next_line() -> str:
            fut: asyncio.Future = loop.create_future()
            def worker():
                try:
                    v = input("sip> ")
                except EOFError:
                    v = "quit"
                except BaseException as e:  # noqa: BLE001
                    loop.call_soon_threadsafe(
                        lambda: fut.cancelled() or fut.set_exception(e))
                    return
                loop.call_soon_threadsafe(
                    lambda: fut.cancelled() or fut.set_result(v))
            t = threading.Thread(target=worker, name="sipc-stdin",
                                 daemon=True)
            t.start()
            try:
                return await fut
            except asyncio.CancelledError:
                # future 被取消 (主程序退出): 让 daemon 线程随进程结束
                raise
    else:
        it = iter(script_lines)
        async def next_line() -> str:
            try:
                line = next(it)
                print(f"sip> {line}", flush=True)
                return line
            except StopIteration:
                return "quit"

    while True:
        try:
            raw = (await next_line()).strip()
        except KeyboardInterrupt:
            break
        if not raw or raw.startswith("#"):
            continue
        # 把中文输入法下常见的全角空格 / 全角标点替换成半角，
        # 避免 shlex 把 "msg 1002　hello" 当成两个 token。
        raw = raw.replace("\u3000", " ").replace("\xa0", " ")
        try:
            parts = shlex.split(raw)
        except ValueError:
            parts = raw.split()
        cmd = parts[0].lower()
        args = parts[1:]
        try:
            if cmd in ("quit", "exit"):
                break
            elif cmd == "help":
                print(HELP)
            elif cmd == "register":
                ok = await ua.register()
                print("OK" if ok else "FAIL")
            elif cmd == "unregister":
                await ua.unregister(); print("OK")
            elif cmd == "options":
                code = await ua.options_ping()
                print(f"OPTIONS -> {code}")
            elif cmd == "msg" and len(args) >= 2:
                ok, mid = await ua.send_message(args[0], " ".join(args[1:]))
                if ok:
                    print(f"OK msgid={mid}" if mid else "OK")
                else:
                    print("FAIL")
            elif cmd == "read" and len(args) == 2:
                ok = await ua.mark_read(args[0], args[1])
                print("OK" if ok else "FAIL")
            elif cmd == "call" and len(args) == 1:
                await ua.call(args[0])
            elif cmd == "answer":
                await ua.answer()
            elif cmd == "reject":
                await ua.reject()
            elif cmd == "hangup":
                await ua.hangup()
            elif cmd == "status":
                active = ua.dialogs.get(ua.active_call) if ua.active_call else None
                rtp = active.rtp if active else None
                print(json.dumps({
                    "registered": ua.registered,
                    "local": f"{ua.local_ip}:{ua.actual_local_port}",
                    "active_call": ua.active_call,
                    "dialogs": list(ua.dialogs.keys()),
                    "rtp": {
                        "enabled": bool(rtp),
                        "remote": f"{rtp.remote[0]}:{rtp.remote[1]}" if rtp and rtp.remote else None,
                        "last_rx_from": f"{rtp.last_rx_from[0]}:{rtp.last_rx_from[1]}" if rtp and rtp.last_rx_from else None,
                        "pkts_sent": rtp.pkts_sent if rtp else 0,
                        "pkts_recv": rtp.pkts_recv if rtp else 0,
                        "bytes_sent": rtp.bytes_sent if rtp else 0,
                        "bytes_recv": rtp.bytes_recv if rtp else 0,
                        "audio_enabled": rtp.use_audio if rtp else False,
                    },
                }, ensure_ascii=False, indent=2))
            elif cmd == "who":
                print(json.dumps(api.list_accounts(), ensure_ascii=False, indent=2))
            elif cmd == "calls":
                print(json.dumps(api.list_calls(), ensure_ascii=False, indent=2))
            elif cmd == "hist":
                u = args[0] if args else None
                print(json.dumps(api.list_messages(u), ensure_ascii=False, indent=2))
            elif cmd == "upload" and args:
                to = args[1] if len(args) > 1 else None
                print(json.dumps(api.upload_voice(args[0], to), ensure_ascii=False, indent=2))
            elif cmd == "api-msg" and len(args) >= 2:
                print(json.dumps(api.send_message_via_api(args[0], " ".join(args[1:])),
                                 ensure_ascii=False, indent=2))
            elif cmd == "rest-hangup" and args:
                print(json.dumps(api.hangup_call(args[0]), ensure_ascii=False, indent=2))
            elif cmd == "friends":
                print(json.dumps(user_api.list_friends(), ensure_ascii=False, indent=2))
            elif cmd == "friend-add" and args:
                note = " ".join(args[1:]) if len(args) > 1 else None
                print(json.dumps(user_api.request_friend(args[0], note),
                                 ensure_ascii=False, indent=2))
            elif cmd == "friend-accept" and args:
                print(json.dumps(user_api.accept_friend(int(args[0])),
                                 ensure_ascii=False, indent=2))
            elif cmd == "friend-reject" and args:
                print(json.dumps(user_api.reject_friend(int(args[0])),
                                 ensure_ascii=False, indent=2))
            elif cmd == "friend-del" and args:
                print(json.dumps(user_api.delete_friend(int(args[0])),
                                 ensure_ascii=False, indent=2))
            elif cmd == "qr":
                ttl = int(args[0]) if args else 600
                note = " ".join(args[1:]) if len(args) > 1 else None
                inv = user_api.create_invite(ttl=ttl, note=note)
                print(f"邀请 token: {inv['token']}")
                print(f"payload  : {inv['payload']}")
                print(f"过期时间 : {inv['expires_at']}")
                print()
                print(render_qr(inv["payload"]))
            elif cmd == "invites":
                print(json.dumps(user_api.list_invites(), ensure_ascii=False, indent=2))
            elif cmd == "scan" and args:
                note = " ".join(args[1:]) if len(args) > 1 else None
                print(json.dumps(user_api.scan_invite(args[0], note),
                                 ensure_ascii=False, indent=2))
            elif cmd == "scan-uri" and args:
                # sipfriend://realm/owner?token=XYZ
                m = re.search(r"token=([^&\s]+)", args[0])
                if not m:
                    print("URI 中未找到 token=")
                else:
                    print(json.dumps(user_api.scan_invite(m.group(1)),
                                     ensure_ascii=False, indent=2))
            elif cmd == "sleep" and args:
                await asyncio.sleep(float(args[0]))
            elif cmd == "set" and len(args) == 2 and args[0] == "audio":
                ua.use_audio = (args[1] == "on")
                print(f"use_audio={ua.use_audio}")
            else:
                print("未知命令，help 查看帮助")
        except Exception as e:
            print(f"ERR: {e}")


# =====================================================================
# main
# =====================================================================

# 默认 JSON 配置文件路径：与 sip_client.py 同目录的 client_config.json
DEFAULT_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                   "client_config.json")

# CLI 参数名 → JSON 字段名（破折号转下划线即可，这里显式列出便于校验）
_CFG_KEYS = [
    "server", "sip_port", "local_port", "user", "password", "realm",
    "rtp_port", "codec", "no_audio", "auto_answer", "no_auto_read",
    "api_base", "admin_user", "admin_password", "script", "no_register",
    "debug", "local_ip",
]

_CONFIG_TEMPLATE = {
    "server": "120.27.145.121",
    "sip_port": 5060,
    "user": "1001",
    "password": "secret123",
    "realm": "sip.example.com",
    "codec": "pcmu",
    "api_base": "http://120.27.145.121:8000",
    "admin_user": "",
    "admin_password": "",
    "no_audio": False,
    "auto_answer": False,
    "no_auto_read": False,
    "no_register": False,
    "debug": False,
    "local_ip": "",
    "local_port": 0,
    "rtp_port": 0,
    "script": ""
}


def _load_json_config(path: str) -> Dict:
    """读取 JSON 配置文件；若不存在则写入模板并返回空 dict。"""
    if not os.path.exists(path):
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(_CONFIG_TEMPLATE, f, ensure_ascii=False, indent=2)
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            print(f"[*] 已生成示例配置: {path}\n    请填入 server/user/password 后再次启动。",
                  file=sys.stderr)
        except OSError as e:
            print(f"[!] 无法创建配置文件 {path}: {e}", file=sys.stderr)
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        print(f"[!] 读取配置文件失败 {path}: {e}", file=sys.stderr)
        return {}
    if not isinstance(data, dict):
        print(f"[!] 配置文件格式错误 (顶层应为对象): {path}", file=sys.stderr)
        return {}
    unknown = [k for k in data if k not in _CFG_KEYS and k != "_comment"]
    if unknown:
        print(f"[!] 配置中存在未知字段 (已忽略): {unknown}", file=sys.stderr)
    return data


def parse_args():
    # 先扫一遍 sys.argv 找 --config，以便用 JSON 提供默认值
    pre = argparse.ArgumentParser(add_help=False)
    pre.add_argument("--config", default=DEFAULT_CONFIG_PATH)
    pre.add_argument("--no-config", action="store_true",
                     help="忽略 JSON 配置文件，仅使用命令行/默认值")
    pre_args, _ = pre.parse_known_args()
    cfg: Dict = {} if pre_args.no_config else _load_json_config(pre_args.config)

    def _cfg(name, default=None):
        v = cfg.get(name)
        return default if v is None else v

    ap = argparse.ArgumentParser(
        description="SIP-VOIP-SERVER PC 测试客户端",
        parents=[pre],
    )
    ap.add_argument("--server",
                    required=("server" not in cfg or not cfg.get("server")),
                    default=_cfg("server"))
    ap.add_argument("--sip-port", type=int, default=_cfg("sip_port", 5060))
    ap.add_argument("--local-port", type=int, default=_cfg("local_port", 0))
    ap.add_argument("--local-ip", default=_cfg("local_ip", ""),
                    help="强制本机在 SIP/SDP 中使用的 IP（多网卡/VPN 时可修复无声）")
    ap.add_argument("--user",
                    required=("user" not in cfg or not cfg.get("user")),
                    default=_cfg("user"))
    ap.add_argument("--password",
                    required=("password" not in cfg or not cfg.get("password")),
                    default=_cfg("password"))
    ap.add_argument("--realm", default=_cfg("realm", "sip.example.com"))
    ap.add_argument("--rtp-port", type=int, default=_cfg("rtp_port", 0))
    ap.add_argument("--codec", default=_cfg("codec", "pcmu"),
                    choices=["pcmu", "pcma"])
    ap.add_argument("--no-audio", action="store_true",
                    default=bool(_cfg("no_audio", False)))
    ap.add_argument("--auto-answer", action="store_true",
                    default=bool(_cfg("auto_answer", False)))
    ap.add_argument("--no-auto-read", action="store_true",
                    default=bool(_cfg("no_auto_read", False)),
                    help="收到消息后不自动发送已读回执")
    ap.add_argument("--api-base", default=_cfg("api_base", ""))
    ap.add_argument("--admin-user", default=_cfg("admin_user", ""))
    ap.add_argument("--admin-password", default=_cfg("admin_password", ""))
    ap.add_argument("--script", default=_cfg("script", ""))
    ap.add_argument("--no-register", action="store_true",
                    default=bool(_cfg("no_register", False)),
                    help="启动时不自动注册")
    ap.add_argument("--debug", action="store_true",
                    default=bool(_cfg("debug", False)))
    return ap.parse_args()


async def amain(args):
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    ua = SipUA(
        server_host=args.server, server_port=args.sip_port,
        user=args.user, password=args.password, realm=args.realm,
        local_port=args.local_port, rtp_port=args.rtp_port,
        local_ip_override=args.local_ip,
        codec=args.codec, use_audio=not args.no_audio,
        auto_answer=args.auto_answer,
        auto_read=not args.no_auto_read,
    )
    api = AdminAPI(args.api_base, args.admin_user, args.admin_password)
    user_api = UserAPI(args.api_base, args.user, args.password)
    await ua.start()
    if args.api_base and args.admin_user:
        api.login()
    if args.api_base:
        user_api.login()
    if not args.no_register:
        ok = await ua.register()
        print(f"REGISTER {'OK' if ok else 'FAIL'}")
    script_lines = None
    if args.script:
        with open(args.script) as f:
            script_lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    try:
        await repl(ua, api, user_api, script_lines)
    finally:
        try:
            await ua.unregister()
        except Exception:
            pass
        await ua.stop()


def main():
    args = parse_args()
    # 保存终端 tty 设置，退出时恢复，避免 Ctrl+C 后终端 "失灵" (无回显/无换行)
    _saved_tc = None
    try:
        import termios
        if sys.stdin.isatty():
            _saved_tc = termios.tcgetattr(sys.stdin.fileno())
    except Exception:
        _saved_tc = None

    def _restore_tty():
        try:
            if _saved_tc is not None:
                import termios
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, _saved_tc)
            else:
                # 兜底: 调 stty sane 恢复终端
                if sys.stdin.isatty():
                    os.system("stty sane 2>/dev/null")
        except Exception:
            pass

    try:
        asyncio.run(amain(args))
    except KeyboardInterrupt:
        pass
    finally:
        _restore_tty()
        # daemon 的 stdin 读线程可能仍阻塞在 input()，强制退出避免 atexit join 卡死
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)


if __name__ == "__main__":
    main()
