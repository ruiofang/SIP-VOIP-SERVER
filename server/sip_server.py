"""异步 UDP SIP 服务器（B2BUA + 媒体中继）。

支持：
  - REGISTER（Digest 鉴权）
  - MESSAGE（短信 / 语音 URL，离线缓存）
  - INVITE / ACK / BYE / CANCEL / re-INVITE：完整 B2BUA
      * Via 入栈 / 出栈 + 事务表保证响应正确路由
      * Contact 重写让 in-dialog 请求始终经过服务器
      * SDP 重写 + RTP 中继分配，实现实时通话
  - OPTIONS（保活）
"""
from __future__ import annotations

import asyncio
import json
import logging
import re
import secrets
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional, Tuple

from sqlalchemy import select

from .auth import gen_nonce, verify_digest
from .config import get_settings
from .db import session_scope
from .models import Message, Registration, SipAccount
from .rtp_relay import RelaySession, RtpRelayManager
from .sdp import rewrite_sdp

logger = logging.getLogger("sip")
settings = get_settings()

CRLF = "\r\n"
CRLF2 = "\r\n\r\n"

Address = Tuple[str, int]


# ============== SIP 报文解析 ==============

@dataclass
class SipMessage:
    raw: bytes
    method: Optional[str] = None
    request_uri: Optional[str] = None
    status_code: Optional[int] = None
    reason: Optional[str] = None
    version: str = "SIP/2.0"
    header_lines: list[Tuple[str, str]] = field(default_factory=list)
    body: bytes = b""

    @property
    def is_request(self) -> bool:
        return self.method is not None

    def header(self, name: str) -> Optional[str]:
        n = name.lower()
        for k, v in self.header_lines:
            if k == n:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.header_lines if k == n]


def parse_sip(data: bytes) -> Optional[SipMessage]:
    try:
        head, _, body = data.partition(b"\r\n\r\n")
        text = head.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines:
            return None
        msg = SipMessage(raw=data, body=body)
        first = lines[0]
        if first.startswith("SIP/"):
            parts = first.split(" ", 2)
            if len(parts) < 3:
                return None
            msg.version = parts[0]
            msg.status_code = int(parts[1])
            msg.reason = parts[2]
        else:
            parts = first.split(" ", 2)
            if len(parts) < 3:
                return None
            msg.method = parts[0].upper()
            msg.request_uri = parts[1]
            msg.version = parts[2]

        cur_name: Optional[str] = None
        cur_value: list[str] = []
        for line in lines[1:]:
            if not line:
                continue
            if line[0] in (" ", "\t") and cur_name is not None:
                cur_value.append(line.strip())
                continue
            if cur_name is not None:
                msg.header_lines.append((cur_name, " ".join(cur_value).strip()))
                cur_name, cur_value = None, []
            if ":" not in line:
                continue
            k, _, v = line.partition(":")
            cur_name = k.strip().lower()
            cur_value = [v.strip()]
        if cur_name is not None:
            msg.header_lines.append((cur_name, " ".join(cur_value).strip()))
        return msg
    except Exception as e:  # noqa
        logger.debug("parse_sip failed: %s", e)
        return None


# ============== 字段解析 ==============

_URI_USER_RE = re.compile(r"sip:([^@>;\s]+)@([^>;\s]+)", re.IGNORECASE)


def extract_uri_user(value: str) -> Optional[str]:
    m = _URI_USER_RE.search(value)
    return m.group(1) if m else None


def extract_uri(value: str) -> Optional[str]:
    m = re.search(r"<([^>]+)>", value)
    raw = m.group(1) if m else value.split(";")[0].strip()
    return raw if raw.lower().startswith("sip:") else None


def parse_kv(value: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for part in re.findall(r'(\w+)\s*=\s*("([^"]*)"|([^,\s]+))', value):
        out[part[0].lower()] = part[2] if part[2] else part[3]
    return out


def parse_via(value: str) -> Tuple[str, int, Dict[str, str]]:
    head, _, params_str = value.partition(";")
    proto, _, hostport = head.rpartition(" ")
    host, port = hostport, 5060
    if ":" in hostport:
        h, p = hostport.rsplit(":", 1)
        host = h
        try:
            port = int(p)
        except ValueError:
            pass
    params: Dict[str, str] = {}
    for kv in params_str.split(";"):
        if not kv:
            continue
        if "=" in kv:
            k, v = kv.split("=", 1)
            params[k.strip().lower()] = v.strip()
        else:
            params[kv.strip().lower()] = ""
    return host, port, params


# ============== 报文重组 ==============

_CANON_MAP = {
    "call-id": "Call-ID", "cseq": "CSeq", "www-authenticate": "WWW-Authenticate",
    "user-agent": "User-Agent", "max-forwards": "Max-Forwards",
    "content-type": "Content-Type", "content-length": "Content-Length",
    "proxy-authorization": "Proxy-Authorization",
}


def _canon(name: str) -> str:
    if name in _CANON_MAP:
        return _CANON_MAP[name]
    return "-".join(p.capitalize() for p in name.split("-"))


def serialize(msg: SipMessage, body: Optional[bytes] = None) -> bytes:
    if msg.is_request:
        first = f"{msg.method} {msg.request_uri} {msg.version}"
    else:
        first = f"{msg.version} {msg.status_code} {msg.reason}"
    final_body = msg.body if body is None else body
    parts = [first]
    has_cl = False
    for k, v in msg.header_lines:
        if k == "content-length":
            v = str(len(final_body))
            has_cl = True
        parts.append(f"{_canon(k)}: {v}")
    if not has_cl:
        parts.append(f"Content-Length: {len(final_body)}")
    head = CRLF.join(parts) + CRLF2
    return head.encode("utf-8") + final_body


def replace_header(msg: SipMessage, name: str, new_value: str) -> None:
    n = name.lower()
    for i, (k, _) in enumerate(msg.header_lines):
        if k == n:
            msg.header_lines[i] = (n, new_value)
            return
    msg.header_lines.append((n, new_value))


def remove_first_header(msg: SipMessage, name: str) -> Optional[str]:
    n = name.lower()
    for i, (k, v) in enumerate(msg.header_lines):
        if k == n:
            del msg.header_lines[i]
            return v
    return None


def prepend_header(msg: SipMessage, name: str, value: str) -> None:
    msg.header_lines.insert(0, (name.lower(), value))


def build_response(req: SipMessage, code: int, reason: str,
                   extra_headers: Optional[Dict[str, str]] = None,
                   body: bytes = b"", content_type: Optional[str] = None) -> bytes:
    lines = [f"SIP/2.0 {code} {reason}"]
    for via in req.header_all("via"):
        lines.append(f"Via: {via}")
    if to := req.header("to"):
        if "tag=" not in to and code >= 200:
            to = f"{to};tag={secrets.token_hex(6)}"
        lines.append(f"To: {to}")
    if frm := req.header("from"):
        lines.append(f"From: {frm}")
    if cid := req.header("call-id"):
        lines.append(f"Call-ID: {cid}")
    if cseq := req.header("cseq"):
        lines.append(f"CSeq: {cseq}")
    lines.append("Server: SIP-VOIP-SERVER/1.0")
    if extra_headers:
        for k, v in extra_headers.items():
            lines.append(f"{k}: {v}")
    if content_type:
        lines.append(f"Content-Type: {content_type}")
    lines.append(f"Content-Length: {len(body)}")
    return (CRLF.join(lines) + CRLF2).encode("utf-8") + body


# ============== Nonce / 在线注册 ==============

class NonceStore:
    def __init__(self, ttl: int = 300) -> None:
        self.ttl = ttl
        self._store: Dict[str, float] = {}

    def issue(self) -> str:
        n = gen_nonce()
        self._store[n] = time.time() + self.ttl
        return n

    def is_valid(self, nonce: str) -> bool:
        exp = self._store.get(nonce)
        if not exp:
            return False
        if exp < time.time():
            self._store.pop(nonce, None)
            return False
        return True

    def cleanup(self) -> None:
        now = time.time()
        for k in list(self._store):
            if self._store[k] < now:
                self._store.pop(k, None)


@dataclass
class OnlineRecord:
    username: str
    contact_uri: str
    source: Address
    expires_at: float
    user_agent: str = ""


# 状态回执的 Content-Type；客户端读完一条消息后会通过 SIP MESSAGE 把
# {"msg_id": N, "status": "read"} 发给服务端，服务端识别后更新数据库并
# 推送给原发送方。
STATUS_CT = "application/x-message-status+json"

# 投递参数
DELIVERY_RETRY_INTERVAL = 4.0   # 单次重试间隔（秒）
DELIVERY_MAX_ATTEMPTS = 5       # 最大重试次数
DELIVERY_TX_TIMEOUT = 8.0       # 等待对端 200 OK 的时长


@dataclass
class OutboundMsg:
    """已发往客户端、正在等待 200 OK 的 MESSAGE 事务。"""

    msg_id: int
    branch: str
    from_user: str
    to_user: str
    target: Address
    sent_at: float
    attempts: int = 1
    is_status: bool = False  # 状态回执（不需要再 ack/重发）


# ============== B2BUA 事务/对话 ==============

@dataclass
class Transaction:
    branch: str
    method: str
    origin_addr: Address
    forwarded_to: Address
    call_id: str
    created_at: float = field(default_factory=time.time)


@dataclass
class Dialog:
    call_id: str
    caller_user: str
    callee_user: str
    caller_addr: Address
    callee_addr: Optional[Address] = None
    relay: Optional[RelaySession] = None
    created_at: float = field(default_factory=time.time)
    confirmed: bool = False
    ended: bool = False


# ============== 主协议 ==============

class SipServerProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.nonces = NonceStore()
        self.online: Dict[str, OnlineRecord] = {}
        self.transactions: Dict[str, Transaction] = {}
        self.dialogs: Dict[str, Dialog] = {}
        # 等待对端 200 OK 的服务端发起 MESSAGE 事务（投递跟踪）
        self.pending_outbound: Dict[str, OutboundMsg] = {}
        self.relay = RtpRelayManager(
            host=settings.sip_host,
            public_host=settings.public_host,
            port_min=settings.rtp_port_min,
            port_max=settings.rtp_port_max,
        )
        self._gc_task: Optional[asyncio.Task] = None
        self._retry_task: Optional[asyncio.Task] = None

    # ---------- asyncio ----------
    def connection_made(self, transport: asyncio.BaseTransport) -> None:  # type: ignore[override]
        self.transport = transport  # type: ignore[assignment]
        logger.info("SIP server listening on %s:%s", settings.sip_host, settings.sip_port)
        self._gc_task = asyncio.get_event_loop().create_task(self._gc_loop())
        self._retry_task = asyncio.get_event_loop().create_task(self._retry_loop())

    def datagram_received(self, data: bytes, addr) -> None:  # type: ignore[override]
        asyncio.create_task(self._handle(data, addr))

    def error_received(self, exc: Exception) -> None:  # type: ignore[override]
        logger.warning("UDP error: %s", exc)

    async def _gc_loop(self) -> None:
        while True:
            try:
                await asyncio.sleep(30)
                self.nonces.cleanup()
                now = time.time()
                for u in [u for u, r in self.online.items() if r.expires_at < now]:
                    self.online.pop(u, None)
                    logger.info("Registration expired: %s", u)
                for b in [b for b, t in self.transactions.items() if now - t.created_at > 32]:
                    self.transactions.pop(b, None)
                stale = [c for c, d in self.dialogs.items()
                         if not d.confirmed and now - d.created_at > 60]
                for c in stale:
                    await self._end_dialog(c)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("gc loop error")

    def send(self, data: bytes, addr: Address) -> None:
        assert self.transport is not None
        self.transport.sendto(data, addr)

    async def _handle(self, data: bytes, addr: Address) -> None:
        msg = parse_sip(data)
        if not msg:
            return
        try:
            if msg.is_request:
                await self._on_request(msg, addr)
            else:
                await self._on_response(msg, addr)
        except Exception:
            logger.exception("handler error")
            if msg.is_request:
                try:
                    self.send(build_response(msg, 500, "Server Internal Error"), addr)
                except Exception:
                    logger.exception("failed to send 500 response")

    # ============== 请求 ==============
    async def _on_request(self, msg: SipMessage, addr: Address) -> None:
        method = msg.method
        if method == "REGISTER":
            await self._handle_register(msg, addr)
        elif method == "MESSAGE":
            await self._handle_message(msg, addr)
        elif method == "OPTIONS":
            self.send(build_response(msg, 200, "OK"), addr)
        elif method == "INVITE":
            await self._handle_invite(msg, addr)
        elif method == "ACK":
            await self._handle_ack(msg, addr)
        elif method in ("BYE", "CANCEL", "INFO", "UPDATE", "REFER", "NOTIFY", "PRACK"):
            await self._handle_in_dialog_request(msg, addr)
        else:
            self.send(build_response(msg, 501, "Not Implemented"), addr)

    # ============== 响应 ==============
    async def _on_response(self, msg: SipMessage, addr: Address) -> None:
        top_via = remove_first_header(msg, "via")
        if not top_via:
            return
        _, _, params = parse_via(top_via)
        branch = params.get("branch", "")

        # 服务端主动发出的 MESSAGE 投递事务 —— 收到 2xx 表示对端签收
        out = self.pending_outbound.get(branch)
        if out is not None:
            self.pending_outbound.pop(branch, None)
            if msg.status_code and 200 <= msg.status_code < 300:
                if not out.is_status:
                    await self._mark_delivered(out)
            else:
                logger.info("outbound MESSAGE failed: msg_id=%s status=%s",
                            out.msg_id, msg.status_code)
                # 失败暂不立即重试，由 _retry_loop 周期性扫描
            return

        tx = self.transactions.get(branch)
        if not tx:
            logger.debug("orphan response, branch=%s", branch)
            return

        dlg = self.dialogs.get(tx.call_id)
        if dlg and dlg.callee_addr is None and addr != dlg.caller_addr:
            dlg.callee_addr = addr

        if tx.method == "INVITE":
            if msg.body:
                ctype = (msg.header("content-type") or "").lower()
                if "application/sdp" in ctype and dlg and dlg.relay:
                    new_body, info = rewrite_sdp(
                        msg.body, settings.public_host, dlg.relay.b_rtp_port)
                    if info.media_ip and info.media_port:
                        self.relay.hint_remote(dlg.call_id, "B",
                                               (info.media_ip, info.media_port))
                    msg.body = new_body
                    replace_header(msg, "content-length", str(len(new_body)))
            self._rewrite_contact(msg)
            if msg.status_code and 200 <= msg.status_code < 300 and dlg:
                dlg.confirmed = True

        if msg.status_code and msg.status_code >= 200:
            self.transactions.pop(branch, None)

        self.send(serialize(msg), tx.origin_addr)

        if tx.method == "BYE" and msg.status_code and msg.status_code >= 200:
            await self._end_dialog(tx.call_id)
        if tx.method == "INVITE" and msg.status_code and msg.status_code >= 300:
            await self._end_dialog(tx.call_id)

    # ============== REGISTER ==============
    async def _handle_register(self, msg: SipMessage, addr: Address) -> None:
        username = extract_uri_user(msg.header("to") or "") or ""
        if not username:
            self.send(build_response(msg, 400, "Bad Request"), addr)
            return
        auth = msg.header("authorization")
        if not auth:
            self._challenge(msg, addr)
            return
        params = parse_kv(auth)
        if not self.nonces.is_valid(params.get("nonce", "")):
            self._challenge(msg, addr, stale=True)
            return

        async with session_scope() as db:
            res = await db.execute(select(SipAccount).where(SipAccount.username == username))
            account = res.scalar_one_or_none()
            if not account or not account.enabled:
                self.send(build_response(msg, 403, "Forbidden"), addr)
                return
            if not verify_digest(
                method="REGISTER",
                uri=params.get("uri", msg.request_uri or ""),
                realm=params.get("realm", settings.sip_realm),
                nonce=params.get("nonce", ""),
                response=params.get("response", ""),
                ha1=account.ha1,
                qop=params.get("qop"),
                nc=params.get("nc"),
                cnonce=params.get("cnonce"),
            ):
                self.send(build_response(msg, 403, "Forbidden"), addr)
                return

            contact = msg.header("contact") or ""
            contact_uri = extract_uri(contact) or f"sip:{username}@{addr[0]}:{addr[1]}"
            expires_h = msg.header("expires")
            expires = int(expires_h) if expires_h and expires_h.isdigit() else 3600
            m = re.search(r"expires\s*=\s*(\d+)", contact, re.IGNORECASE)
            if m:
                expires = int(m.group(1))
            ua = msg.header("user-agent") or ""

            if expires == 0:
                self.online.pop(username, None)
                await db.execute(
                    Registration.__table__.delete().where(Registration.account_id == account.id))
            else:
                exp_dt = datetime.now(timezone.utc) + timedelta(seconds=expires)
                self.online[username] = OnlineRecord(
                    username=username, contact_uri=contact_uri, source=addr,
                    expires_at=time.time() + expires, user_agent=ua)
                res2 = await db.execute(
                    select(Registration).where(Registration.account_id == account.id))
                reg = res2.scalar_one_or_none()
                if reg:
                    reg.contact_uri = contact_uri
                    reg.source_ip, reg.source_port = addr[0], addr[1]
                    reg.expires_at = exp_dt
                    reg.user_agent = ua
                else:
                    db.add(Registration(
                        account_id=account.id, contact_uri=contact_uri,
                        source_ip=addr[0], source_port=addr[1],
                        expires_at=exp_dt, user_agent=ua))

        self.send(build_response(msg, 200, "OK", extra_headers={
            "Contact": f"{contact_uri};expires={expires}",
            "Expires": str(expires),
        }), addr)

        if expires > 0:
            await self._deliver_offline(username)

    def _challenge(self, msg: SipMessage, addr: Address, *, stale: bool = False) -> None:
        nonce = self.nonces.issue()
        chal = (f'Digest realm="{settings.sip_realm}", nonce="{nonce}", '
                f'algorithm=MD5, qop="auth"')
        if stale:
            chal += ", stale=true"
        self.send(build_response(msg, 401, "Unauthorized",
                                 extra_headers={"WWW-Authenticate": chal}), addr)

    # ============== MESSAGE ==============
    async def _handle_message(self, msg: SipMessage, addr: Address) -> None:
        from_user = extract_uri_user(msg.header("from") or "") or ""
        to_user = (extract_uri_user(msg.header("to") or "")
                   or extract_uri_user(msg.request_uri or "") or "")
        if not (from_user and to_user):
            self.send(build_response(msg, 400, "Bad Request"), addr)
            return
        if not await self._require_auth(msg, addr, from_user, method="MESSAGE"):
            return

        ctype = msg.header("content-type") or "text/plain"
        body_text = msg.body.decode("utf-8", errors="replace")

        # ---- 状态回执：客户端读完后发回 ----
        if STATUS_CT in ctype.lower():
            self.send(build_response(msg, 200, "OK"), addr)
            await self._handle_status_receipt(from_user, body_text)
            return

        is_voice = "application/x-voice-url" in ctype.lower() or body_text.startswith("voice://")
        msg_type = "voice" if is_voice else "text"

        async with session_scope() as db:
            row = Message(from_user=from_user, to_user=to_user,
                          msg_type=msg_type, body=body_text,
                          delivered=False, status="pending", attempts=0)
            db.add(row)
            await db.flush()
            row_id = row.id

        # 200 OK + X-Message-ID 让发送方记录服务端 ID，后续状态推送可关联
        self.send(build_response(msg, 200, "OK", extra_headers={
            "X-Message-ID": str(row_id),
        }), addr)

        await self._try_deliver(row_id, from_user, to_user, body_text, ctype)

    async def _try_deliver(self, msg_id: int, from_user: str, to_user: str, body: str,
                           content_type: str) -> None:
        rec = self.online.get(to_user)
        if not rec:
            logger.info("offline message stored: %s -> %s (id=%s)",
                        from_user, to_user, msg_id)
            return
        await self._dispatch_message(msg_id, rec, from_user, to_user, body, content_type)

    async def _dispatch_message(self, msg_id: int, rec: OnlineRecord,
                                from_user: str, to_user: str,
                                body: str, content_type: str) -> None:
        """构造 SIP MESSAGE 发给在线客户端，并跟踪 200 OK。"""
        body_b = body.encode("utf-8")
        call_id = secrets.token_hex(12)
        branch = "z9hG4bK" + secrets.token_hex(6)
        from_tag = secrets.token_hex(6)
        host, port = settings.public_host, settings.public_sip_port
        lines = [
            f"MESSAGE {rec.contact_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {host}:{port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{from_user}@{settings.sip_realm}>;tag={from_tag}",
            f"To: <sip:{to_user}@{settings.sip_realm}>",
            f"Call-ID: {call_id}",
            "CSeq: 1 MESSAGE",
            f"Content-Type: {content_type}",
            f"X-Message-ID: {msg_id}",
            f"Content-Length: {len(body_b)}",
        ]
        pkt = (CRLF.join(lines) + CRLF2).encode("utf-8") + body_b
        self.send(pkt, rec.source)
        async with session_scope() as db:
            obj = await db.get(Message, msg_id)
            if obj:
                obj.attempts = (obj.attempts or 0) + 1
                obj.last_attempt_at = datetime.now(timezone.utc)
                attempts = obj.attempts
            else:
                attempts = 1
        self.pending_outbound[branch] = OutboundMsg(
            msg_id=msg_id, branch=branch, from_user=from_user, to_user=to_user,
            target=rec.source, sent_at=time.time(), attempts=attempts,
        )

    async def _mark_delivered(self, out: OutboundMsg) -> None:
        async with session_scope() as db:
            obj = await db.get(Message, out.msg_id)
            if not obj:
                return
            if obj.status == "read":  # 已读保留
                return
            obj.status = "delivered"
            obj.delivered = True
            obj.delivered_at = datetime.now(timezone.utc)
        logger.info("MESSAGE delivered: id=%s %s -> %s",
                    out.msg_id, out.from_user, out.to_user)
        await self._notify_status_to_sender(out.msg_id, out.from_user,
                                            out.to_user, "delivered")

    async def _handle_status_receipt(self, from_user: str, body: str) -> None:
        """客户端发回的已读回执：{"msg_id": N, "status": "read"}"""
        try:
            data = json.loads(body)
            msg_id = int(data.get("msg_id"))
            status = str(data.get("status") or "read")
        except Exception:
            logger.warning("invalid status receipt from %s: %r", from_user, body[:200])
            return
        if status not in ("read", "delivered"):
            return

        async with session_scope() as db:
            obj = await db.get(Message, msg_id)
            if not obj:
                return
            # 仅允许接收方对该消息发回执
            if obj.to_user != from_user:
                logger.warning("status receipt user mismatch: msg_id=%s "
                               "to_user=%s receipt_from=%s",
                               msg_id, obj.to_user, from_user)
                return
            if status == "read":
                obj.status = "read"
                obj.read_at = datetime.now(timezone.utc)
                if not obj.delivered:
                    obj.delivered = True
                    obj.delivered_at = obj.read_at
            elif status == "delivered" and obj.status == "pending":
                obj.status = "delivered"
                obj.delivered = True
                obj.delivered_at = datetime.now(timezone.utc)
            sender = obj.from_user
            recipient = obj.to_user

        logger.info("MESSAGE %s: id=%s %s -> %s", status, msg_id, sender, recipient)
        await self._notify_status_to_sender(msg_id, sender, recipient, status)

    async def _notify_status_to_sender(self, msg_id: int, sender: str,
                                       recipient: str, status: str) -> None:
        rec = self.online.get(sender)
        if not rec:
            return
        payload = json.dumps({"msg_id": msg_id, "status": status,
                              "to": recipient}, ensure_ascii=False)
        body_b = payload.encode("utf-8")
        call_id = secrets.token_hex(12)
        branch = "z9hG4bK" + secrets.token_hex(6)
        from_tag = secrets.token_hex(6)
        host, port = settings.public_host, settings.public_sip_port
        lines = [
            f"MESSAGE {rec.contact_uri} SIP/2.0",
            f"Via: SIP/2.0/UDP {host}:{port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{recipient}@{settings.sip_realm}>;tag={from_tag}",
            f"To: <sip:{sender}@{settings.sip_realm}>",
            f"Call-ID: {call_id}",
            "CSeq: 1 MESSAGE",
            f"Content-Type: {STATUS_CT}",
            f"Content-Length: {len(body_b)}",
        ]
        pkt = (CRLF.join(lines) + CRLF2).encode("utf-8") + body_b
        self.send(pkt, rec.source)
        # 状态回执自身不要求重传
        self.pending_outbound[branch] = OutboundMsg(
            msg_id=msg_id, branch=branch, from_user=recipient, to_user=sender,
            target=rec.source, sent_at=time.time(), attempts=1, is_status=True,
        )

    async def _deliver_offline(self, username: str) -> None:
        async with session_scope() as db:
            res = await db.execute(
                select(Message).where(
                    Message.to_user == username,
                    Message.status.in_(("pending",)),
                ).order_by(Message.created_at)
            )
            rows = list(res.scalars())
        rec = self.online.get(username)
        if not rec:
            return
        for r in rows:
            ctype = ("application/x-voice-url" if r.msg_type == "voice"
                     else "text/plain;charset=utf-8")
            await self._dispatch_message(r.id, rec, r.from_user, r.to_user,
                                         r.body, ctype)

    async def _retry_loop(self) -> None:
        """周期性扫描 pending 消息，处理超时未确认 / 重试投递。"""
        while True:
            try:
                await asyncio.sleep(DELIVERY_RETRY_INTERVAL)
                now = time.time()

                # 1. 处理超时的 pending_outbound（对端 200 OK 没回）
                stale = [b for b, o in self.pending_outbound.items()
                         if now - o.sent_at > DELIVERY_TX_TIMEOUT]
                for b in stale:
                    o = self.pending_outbound.pop(b, None)
                    if o and not o.is_status:
                        logger.info("outbound MESSAGE timeout: id=%s attempts=%d",
                                    o.msg_id, o.attempts)

                # 2. 扫描 DB 中仍 pending 的消息，对在线对端重试
                async with session_scope() as db:
                    res = await db.execute(
                        select(Message).where(Message.status == "pending")
                        .order_by(Message.created_at).limit(200)
                    )
                    rows = list(res.scalars())

                in_flight_ids = {o.msg_id for o in self.pending_outbound.values()
                                 if not o.is_status}
                for r in rows:
                    if r.id in in_flight_ids:
                        continue
                    rec = self.online.get(r.to_user)
                    if not rec:
                        continue
                    if (r.attempts or 0) >= DELIVERY_MAX_ATTEMPTS:
                        async with session_scope() as db:
                            obj = await db.get(Message, r.id)
                            if obj and obj.status == "pending":
                                obj.status = "failed"
                        logger.warning("MESSAGE failed after %d attempts: id=%s",
                                       r.attempts, r.id)
                        continue
                    # 节流：若上次尝试不久前，跳过
                    last = r.last_attempt_at
                    if last is not None:
                        if last.tzinfo is None:
                            last = last.replace(tzinfo=timezone.utc)
                        if (datetime.now(timezone.utc) - last).total_seconds() \
                                < DELIVERY_RETRY_INTERVAL:
                            continue
                    ctype = ("application/x-voice-url" if r.msg_type == "voice"
                             else "text/plain;charset=utf-8")
                    await self._dispatch_message(r.id, rec, r.from_user,
                                                 r.to_user, r.body, ctype)
            except asyncio.CancelledError:
                break
            except Exception:
                logger.exception("retry loop error")

    # ============== INVITE ==============
    async def _handle_invite(self, msg: SipMessage, addr: Address) -> None:
        from_user = extract_uri_user(msg.header("from") or "") or ""
        to_user = (extract_uri_user(msg.request_uri or "")
                   or extract_uri_user(msg.header("to") or "") or "")
        if not (from_user and to_user):
            self.send(build_response(msg, 400, "Bad Request"), addr)
            return

        call_id = msg.header("call-id") or ""
        is_reinvite = call_id in self.dialogs
        dlg: Dialog
        target: Address

        if not is_reinvite:
            if not await self._require_auth(msg, addr, from_user, method="INVITE"):
                return
            rec = self.online.get(to_user)
            if not rec:
                self.send(build_response(msg, 404, "Not Found"), addr)
                return
            self.send(build_response(msg, 100, "Trying"), addr)
            relay = await self.relay.allocate(call_id)
            dlg = Dialog(call_id=call_id, caller_user=from_user, callee_user=to_user,
                         caller_addr=addr, relay=relay)
            self.dialogs[call_id] = dlg
            target = rec.source
        else:
            dlg = self.dialogs[call_id]
            if dlg.callee_addr is None:
                self.send(build_response(msg, 500, "No Route"), addr)
                return
            target = dlg.callee_addr if addr == dlg.caller_addr else dlg.caller_addr

        if msg.body and dlg.relay:
            ctype = (msg.header("content-type") or "").lower()
            if "application/sdp" in ctype:
                # 主叫方向：用 leg_a 端口；被叫方向（re-INVITE 反向）：用 leg_b
                relay_port = (dlg.relay.a_rtp_port if addr == dlg.caller_addr
                              else dlg.relay.b_rtp_port)
                leg = "A" if addr == dlg.caller_addr else "B"
                new_body, info = rewrite_sdp(msg.body, settings.public_host, relay_port)
                if info.media_ip and info.media_port:
                    self.relay.hint_remote(call_id, leg, (info.media_ip, info.media_port))
                msg.body = new_body
                replace_header(msg, "content-length", str(len(new_body)))

        self._rewrite_contact(msg)
        await self._forward_request(msg, addr, target)

    async def _handle_ack(self, msg: SipMessage, addr: Address) -> None:
        call_id = msg.header("call-id") or ""
        dlg = self.dialogs.get(call_id)
        if not dlg:
            return
        target = dlg.callee_addr if addr == dlg.caller_addr else dlg.caller_addr
        if not target:
            return
        branch = "z9hG4bK" + secrets.token_hex(8)
        self._push_top_via(msg, branch)
        self._rewrite_contact(msg)
        self.send(serialize(msg), target)

    async def _handle_in_dialog_request(self, msg: SipMessage, addr: Address) -> None:
        call_id = msg.header("call-id") or ""
        dlg = self.dialogs.get(call_id)
        if not dlg:
            self.send(build_response(msg, 481, "Call/Transaction Does Not Exist"), addr)
            return
        if addr == dlg.caller_addr:
            target = dlg.callee_addr
        elif dlg.callee_addr and addr == dlg.callee_addr:
            target = dlg.caller_addr
        else:
            target = dlg.callee_addr or dlg.caller_addr
        if not target:
            self.send(build_response(msg, 500, "No Route"), addr)
            return
        self._rewrite_contact(msg)
        await self._forward_request(msg, addr, target)

    # ============== 转发请求 ==============
    async def _forward_request(self, msg: SipMessage, origin: Address, target: Address) -> None:
        branch = "z9hG4bK" + secrets.token_hex(8)
        self._push_top_via(msg, branch)
        mf = msg.header("max-forwards")
        if mf and mf.isdigit():
            replace_header(msg, "max-forwards", str(max(0, int(mf) - 1)))
        else:
            replace_header(msg, "max-forwards", "70")

        call_id = msg.header("call-id") or ""
        if msg.method != "ACK":
            self.transactions[branch] = Transaction(
                branch=branch, method=msg.method or "", origin_addr=origin,
                forwarded_to=target, call_id=call_id)
        self.send(serialize(msg), target)

    def _push_top_via(self, msg: SipMessage, branch: str) -> None:
        host, port = settings.public_host, settings.public_sip_port
        prepend_header(msg, "Via", f"SIP/2.0/UDP {host}:{port};branch={branch};rport")

    def _rewrite_contact(self, msg: SipMessage) -> None:
        contact = msg.header("contact")
        if not contact:
            return
        user = extract_uri_user(contact) or ""
        host, port = settings.public_host, settings.public_sip_port
        replace_header(msg, "contact", f"<sip:{user}@{host}:{port}>")

    async def _end_dialog(self, call_id: str) -> None:
        dlg = self.dialogs.pop(call_id, None)
        if dlg and not dlg.ended:
            dlg.ended = True
            await self.relay.release(call_id)

    # ============== Auth helper ==============
    async def _require_auth(self, msg: SipMessage, addr: Address, username: str, *,
                            method: str) -> bool:
        auth = msg.header("authorization") or msg.header("proxy-authorization")
        if not auth:
            self._challenge(msg, addr)
            return False
        params = parse_kv(auth)
        if not self.nonces.is_valid(params.get("nonce", "")):
            self._challenge(msg, addr, stale=True)
            return False
        async with session_scope() as db:
            res = await db.execute(select(SipAccount).where(SipAccount.username == username))
            account = res.scalar_one_or_none()
            if not account or not account.enabled:
                self.send(build_response(msg, 403, "Forbidden"), addr)
                return False
            if not verify_digest(
                method=method,
                uri=params.get("uri", msg.request_uri or ""),
                realm=params.get("realm", settings.sip_realm),
                nonce=params.get("nonce", ""),
                response=params.get("response", ""),
                ha1=account.ha1,
                qop=params.get("qop"),
                nc=params.get("nc"),
                cnonce=params.get("cnonce"),
            ):
                self.send(build_response(msg, 403, "Forbidden"), addr)
                return False
        return True

    # ============== 管理端调用 ==============
    def list_calls(self) -> list[dict]:
        out = []
        for cid, d in self.dialogs.items():
            stats = self.relay.get(cid).stats() if d.relay and self.relay.get(cid) else {}
            out.append({
                "call_id": cid,
                "caller": d.caller_user,
                "callee": d.callee_user,
                "caller_addr": f"{d.caller_addr[0]}:{d.caller_addr[1]}",
                "callee_addr": (f"{d.callee_addr[0]}:{d.callee_addr[1]}"
                                if d.callee_addr else None),
                "confirmed": d.confirmed,
                "duration": int(time.time() - d.created_at),
                "relay": stats,
            })
        return out

    async def force_hangup(self, call_id: str) -> bool:
        dlg = self.dialogs.get(call_id)
        if not dlg:
            return False
        for who, addr in [("caller", dlg.caller_addr), ("callee", dlg.callee_addr)]:
            if not addr:
                continue
            other_user = dlg.callee_user if who == "caller" else dlg.caller_user
            self_user = dlg.caller_user if who == "caller" else dlg.callee_user
            self._send_bye(addr, dlg.call_id, self_user, other_user)
        await self._end_dialog(call_id)
        return True

    def _send_bye(self, target: Address, call_id: str, from_user: str, to_user: str) -> None:
        host, port = settings.public_host, settings.public_sip_port
        branch = "z9hG4bK" + secrets.token_hex(6)
        tag = secrets.token_hex(6)
        lines = [
            f"BYE sip:{to_user}@{host}:{port} SIP/2.0",
            f"Via: SIP/2.0/UDP {host}:{port};branch={branch};rport",
            "Max-Forwards: 70",
            f"From: <sip:{from_user}@{settings.sip_realm}>;tag={tag}",
            f"To: <sip:{to_user}@{settings.sip_realm}>",
            f"Call-ID: {call_id}",
            "CSeq: 100 BYE",
            "Content-Length: 0",
        ]
        self.send((CRLF.join(lines) + CRLF2).encode("utf-8"), target)


async def start_sip_server() -> Tuple[asyncio.DatagramTransport, SipServerProtocol]:
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: SipServerProtocol(),
        local_addr=(settings.sip_host, settings.sip_port),
    )
    return transport, protocol  # type: ignore[return-value]
