"""FastAPI 管理后台 + 语音消息上传/下载 + 主动下发 API。"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from .auth import (compute_ha1, create_access_token, decode_token,
                   decode_token_full, hash_password, verify_password)
from .config import get_settings
from .db import get_session, init_db, session_scope
from .models import (Admin, Friendship, InviteToken, Message, Registration,
                     SipAccount, VoiceFile)

logger = logging.getLogger("api")
settings = get_settings()

app = FastAPI(title="SIP-VOIP-SERVER Admin API", version="1.0.0")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


# ============== 启动初始化 ==============
@app.on_event("startup")
async def _startup() -> None:
    await init_db()
    # 创建默认管理员
    async with session_scope() as db:
        res = await db.execute(select(Admin).where(Admin.username == settings.admin_default_user))
        if not res.scalar_one_or_none():
            db.add(Admin(
                username=settings.admin_default_user,
                password_hash=hash_password(settings.admin_default_pass),
                is_super=True,
            ))
            logger.warning("Default admin '%s' created. CHANGE PASSWORD IMMEDIATELY.",
                           settings.admin_default_user)


# ============== 鉴权依赖 ==============
async def current_admin(token: str = Depends(oauth2_scheme),
                        db: AsyncSession = Depends(get_session)) -> Admin:
    sub = decode_token(token)
    if not sub:
        raise HTTPException(401, "Invalid token")
    res = await db.execute(select(Admin).where(Admin.username == sub))
    admin = res.scalar_one_or_none()
    if not admin:
        raise HTTPException(401, "Admin not found")
    return admin


class _Caller:
    """统一的调用者：admin 或 SIP user。"""

    def __init__(self, *, username: str, is_admin: bool):
        self.username = username
        self.is_admin = is_admin


async def current_caller(token: str = Depends(oauth2_scheme),
                         db: AsyncSession = Depends(get_session)) -> _Caller:
    data = decode_token_full(token)
    if not data or not data.get("sub"):
        raise HTTPException(401, "Invalid token")
    sub = data["sub"]
    if data.get("kind") == "user":
        res = await db.execute(select(SipAccount).where(SipAccount.username == sub))
        if not res.scalar_one_or_none():
            raise HTTPException(401, "user not found")
        return _Caller(username=sub, is_admin=False)
    res = await db.execute(select(Admin).where(Admin.username == sub))
    if not res.scalar_one_or_none():
        raise HTTPException(401, "admin not found")
    return _Caller(username=sub, is_admin=True)


# ============== Schema ==============
class LoginResp(BaseModel):
    access_token: str
    token_type: str = "bearer"


class AccountCreate(BaseModel):
    username: str = Field(min_length=2, max_length=64)
    password: str = Field(min_length=4, max_length=128)
    display_name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True


class AccountUpdate(BaseModel):
    password: Optional[str] = Field(default=None, min_length=4, max_length=128)
    display_name: Optional[str] = None
    description: Optional[str] = None
    enabled: Optional[bool] = None


class AccountOut(BaseModel):
    id: int
    username: str
    display_name: Optional[str] = None
    description: Optional[str] = None
    enabled: bool
    online: bool
    contact_uri: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    class Config:
        from_attributes = True


class MessageOut(BaseModel):
    id: int
    from_user: str
    to_user: str
    msg_type: str
    body: str
    delivered: bool
    status: str = "pending"
    attempts: int = 0
    created_at: datetime
    delivered_at: Optional[datetime] = None
    read_at: Optional[datetime] = None
    last_attempt_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SendMessageReq(BaseModel):
    from_user: str
    to_user: str
    body: str
    msg_type: str = "text"   # text / voice


# ============== 认证 ==============
@app.post("/api/auth/login", response_model=LoginResp)
async def login(form: OAuth2PasswordRequestForm = Depends(),
                db: AsyncSession = Depends(get_session)) -> LoginResp:
    res = await db.execute(select(Admin).where(Admin.username == form.username))
    admin = res.scalar_one_or_none()
    if not admin or not verify_password(form.password, admin.password_hash):
        raise HTTPException(401, "Invalid credentials")
    return LoginResp(access_token=create_access_token(admin.username))


@app.post("/api/auth/change_password")
async def change_password(old_password: str = Form(...), new_password: str = Form(...),
                          admin: Admin = Depends(current_admin),
                          db: AsyncSession = Depends(get_session)) -> dict:
    if not verify_password(old_password, admin.password_hash):
        raise HTTPException(400, "wrong old password")
    admin.password_hash = hash_password(new_password)
    db.add(admin)
    await db.commit()
    return {"ok": True}


# ============== SIP 用户自助登录（用于好友功能等） ==============
@app.post("/api/user/login", response_model=LoginResp)
async def user_login(form: OAuth2PasswordRequestForm = Depends(),
                     db: AsyncSession = Depends(get_session)) -> LoginResp:
    """SIP 用户用自身的 SIP 账号密码登录，获取 user-kind JWT。"""
    res = await db.execute(select(SipAccount).where(SipAccount.username == form.username))
    acc = res.scalar_one_or_none()
    if not acc or not acc.enabled:
        raise HTTPException(401, "Invalid credentials")
    if acc.ha1 != compute_ha1(acc.username, acc.realm, form.password):
        raise HTTPException(401, "Invalid credentials")
    return LoginResp(access_token=create_access_token(acc.username, kind="user"))


# ============== 好友 ==============
class FriendRequestReq(BaseModel):
    to_user: str
    note: Optional[str] = None


class FriendOut(BaseModel):
    id: int
    from_user: str
    to_user: str
    peer: str          # 相对调用者的对端
    direction: str     # outgoing/incoming/self
    status: str
    note: Optional[str] = None
    created_at: datetime
    accepted_at: Optional[datetime] = None


class InviteCreateReq(BaseModel):
    note: Optional[str] = None
    ttl_seconds: int = 600


class InviteOut(BaseModel):
    token: str
    owner: str
    payload: str
    expires_at: datetime
    note: Optional[str] = None


class ScanReq(BaseModel):
    token: str
    note: Optional[str] = None


def _friend_to_out(f: Friendship, viewer: str) -> FriendOut:
    if f.from_user == viewer and f.to_user == viewer:
        peer, direction = viewer, "self"
    elif f.from_user == viewer:
        peer, direction = f.to_user, "outgoing"
    elif f.to_user == viewer:
        peer, direction = f.from_user, "incoming"
    else:
        peer, direction = f.to_user, "admin-view"
    return FriendOut(
        id=f.id, from_user=f.from_user, to_user=f.to_user,
        peer=peer, direction=direction,
        status=f.status, note=f.note,
        created_at=f.created_at, accepted_at=f.accepted_at,
    )


async def _existing_friendship(db: AsyncSession, a: str, b: str) -> Optional[Friendship]:
    res = await db.execute(select(Friendship).where(
        ((Friendship.from_user == a) & (Friendship.to_user == b)) |
        ((Friendship.from_user == b) & (Friendship.to_user == a))
    ))
    return res.scalars().first()


@app.get("/api/friends", response_model=list[FriendOut])
async def list_friends(user: Optional[str] = None,
                       caller: _Caller = Depends(current_caller),
                       db: AsyncSession = Depends(get_session)) -> list[FriendOut]:
    """列出好友 / 待处理请求。

    - user-kind token: 只能看自己的（user 参数被忽略）
    - admin token: 不传 user 看全部；传 user 仅看该用户
    """
    if not caller.is_admin:
        target = caller.username
        stmt = select(Friendship).where(
            (Friendship.from_user == target) | (Friendship.to_user == target)
        ).order_by(desc(Friendship.created_at))
    elif user:
        stmt = select(Friendship).where(
            (Friendship.from_user == user) | (Friendship.to_user == user)
        ).order_by(desc(Friendship.created_at))
        target = user
    else:
        stmt = select(Friendship).order_by(desc(Friendship.created_at))
        target = ""
    res = await db.execute(stmt)
    return [_friend_to_out(f, target) for f in res.scalars()]


@app.post("/api/friends/request", response_model=FriendOut)
async def friend_request(payload: FriendRequestReq,
                         caller: _Caller = Depends(current_caller),
                         db: AsyncSession = Depends(get_session)) -> FriendOut:
    """发起好友申请（pending）。仅用户登录可用；admin 想直接代加用 /api/admin/friends。"""
    if caller.is_admin:
        raise HTTPException(400, "admin should use /api/admin/friends")
    if payload.to_user == caller.username:
        raise HTTPException(400, "cannot friend yourself")
    res = await db.execute(select(SipAccount).where(SipAccount.username == payload.to_user))
    if not res.scalar_one_or_none():
        raise HTTPException(404, "target user not found")
    existing = await _existing_friendship(db, caller.username, payload.to_user)
    if existing:
        return _friend_to_out(existing, caller.username)
    f = Friendship(from_user=caller.username, to_user=payload.to_user,
                   status="pending", note=payload.note)
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return _friend_to_out(f, caller.username)


async def _get_friendship(db: AsyncSession, fid: int) -> Friendship:
    res = await db.execute(select(Friendship).where(Friendship.id == fid))
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(404, "friendship not found")
    return f


@app.post("/api/friends/{fid}/accept", response_model=FriendOut)
async def friend_accept(fid: int, caller: _Caller = Depends(current_caller),
                        db: AsyncSession = Depends(get_session)) -> FriendOut:
    f = await _get_friendship(db, fid)
    if not caller.is_admin and caller.username != f.to_user:
        raise HTTPException(403, "only recipient can accept")
    if f.status == "accepted":
        return _friend_to_out(f, caller.username)
    f.status = "accepted"
    f.accepted_at = datetime.now(timezone.utc)
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return _friend_to_out(f, caller.username)


@app.post("/api/friends/{fid}/reject", status_code=204, response_model=None)
async def friend_reject(fid: int, caller: _Caller = Depends(current_caller),
                        db: AsyncSession = Depends(get_session)):
    f = await _get_friendship(db, fid)
    if not caller.is_admin and caller.username != f.to_user:
        raise HTTPException(403, "only recipient can reject")
    await db.delete(f)
    await db.commit()


@app.delete("/api/friends/{fid}", status_code=204, response_model=None)
async def friend_delete(fid: int, caller: _Caller = Depends(current_caller),
                        db: AsyncSession = Depends(get_session)):
    f = await _get_friendship(db, fid)
    if not caller.is_admin and caller.username not in (f.from_user, f.to_user):
        raise HTTPException(403, "forbidden")
    await db.delete(f)
    await db.commit()


@app.post("/api/friends/invite", response_model=InviteOut)
async def friend_invite(payload: InviteCreateReq,
                        caller: _Caller = Depends(current_caller),
                        db: AsyncSession = Depends(get_session)) -> InviteOut:
    """生成扫码邀请令牌。仅 SIP 用户可用。返回 payload 字符串供 QR 编码。"""
    if caller.is_admin:
        raise HTTPException(400, "admin cannot create invite (use a user account)")
    ttl = max(30, min(payload.ttl_seconds, 24 * 3600))
    tok = secrets.token_urlsafe(16)
    exp = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    inv = InviteToken(token=tok, owner=caller.username, note=payload.note, expires_at=exp)
    db.add(inv)
    await db.commit()
    await db.refresh(inv)
    qr_payload = f"sipfriend://{settings.sip_realm}/{caller.username}?token={tok}"
    return InviteOut(token=tok, owner=caller.username, payload=qr_payload,
                     expires_at=exp, note=payload.note)


@app.post("/api/friends/scan", response_model=FriendOut)
async def friend_scan(payload: ScanReq,
                      caller: _Caller = Depends(current_caller),
                      db: AsyncSession = Depends(get_session)) -> FriendOut:
    """扫码加好友：消费 token 后立即建立 accepted 关系。"""
    if caller.is_admin:
        raise HTTPException(400, "scan requires user-kind token")
    res = await db.execute(select(InviteToken).where(InviteToken.token == payload.token))
    inv = res.scalar_one_or_none()
    if not inv:
        raise HTTPException(404, "invalid token")
    if inv.used_by:
        raise HTTPException(410, "token already used")
    exp = inv.expires_at
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=timezone.utc)
    if exp < datetime.now(timezone.utc):
        raise HTTPException(410, "token expired")
    if inv.owner == caller.username:
        raise HTTPException(400, "cannot scan your own invite")
    existing = await _existing_friendship(db, inv.owner, caller.username)
    now = datetime.now(timezone.utc)
    if existing:
        if existing.status != "accepted":
            existing.status = "accepted"
            existing.accepted_at = now
            db.add(existing)
        f = existing
    else:
        f = Friendship(from_user=inv.owner, to_user=caller.username,
                       status="accepted", note=payload.note,
                       accepted_at=now)
        db.add(f)
    inv.used_by = caller.username
    inv.used_at = now
    db.add(inv)
    await db.commit()
    await db.refresh(f)
    return _friend_to_out(f, caller.username)


@app.get("/api/friends/invites", response_model=list[InviteOut])
async def list_my_invites(caller: _Caller = Depends(current_caller),
                          db: AsyncSession = Depends(get_session)) -> list[InviteOut]:
    if caller.is_admin:
        raise HTTPException(400, "admin has no invites")
    res = await db.execute(select(InviteToken).where(
        InviteToken.owner == caller.username
    ).order_by(desc(InviteToken.created_at)).limit(50))
    out = []
    for inv in res.scalars():
        out.append(InviteOut(
            token=inv.token, owner=inv.owner,
            payload=f"sipfriend://{settings.sip_realm}/{inv.owner}?token={inv.token}",
            expires_at=inv.expires_at, note=inv.note,
        ))
    return out


# ---- 管理员：直接建立 / 拉黑好友关系 ----
class AdminFriendCreateReq(BaseModel):
    from_user: str
    to_user: str
    status: str = "accepted"   # pending/accepted/blocked
    note: Optional[str] = None


@app.post("/api/admin/friends", response_model=FriendOut)
async def admin_create_friend(payload: AdminFriendCreateReq,
                              _: Admin = Depends(current_admin),
                              db: AsyncSession = Depends(get_session)) -> FriendOut:
    if payload.status not in ("pending", "accepted", "blocked"):
        raise HTTPException(400, "bad status")
    if payload.from_user == payload.to_user:
        raise HTTPException(400, "from == to")
    for u in (payload.from_user, payload.to_user):
        res = await db.execute(select(SipAccount).where(SipAccount.username == u))
        if not res.scalar_one_or_none():
            raise HTTPException(404, f"user not found: {u}")
    existing = await _existing_friendship(db, payload.from_user, payload.to_user)
    now = datetime.now(timezone.utc)
    if existing:
        existing.status = payload.status
        existing.note = payload.note or existing.note
        if payload.status == "accepted" and not existing.accepted_at:
            existing.accepted_at = now
        db.add(existing)
        await db.commit()
        await db.refresh(existing)
        return _friend_to_out(existing, "")
    f = Friendship(from_user=payload.from_user, to_user=payload.to_user,
                   status=payload.status, note=payload.note,
                   accepted_at=now if payload.status == "accepted" else None)
    db.add(f)
    await db.commit()
    await db.refresh(f)
    return _friend_to_out(f, "")



# ============== 设备账号 CRUD ==============
@app.post("/api/accounts", response_model=AccountOut)
async def create_account(payload: AccountCreate,
                         _: Admin = Depends(current_admin),
                         db: AsyncSession = Depends(get_session)) -> AccountOut:
    res = await db.execute(select(SipAccount).where(SipAccount.username == payload.username))
    if res.scalar_one_or_none():
        raise HTTPException(409, "username exists")
    acc = SipAccount(
        username=payload.username,
        realm=settings.sip_realm,
        ha1=compute_ha1(payload.username, settings.sip_realm, payload.password),
        display_name=payload.display_name,
        description=payload.description,
        enabled=payload.enabled,
    )
    db.add(acc)
    await db.commit()
    await db.refresh(acc)
    return _account_to_out(acc, None)


@app.get("/api/accounts", response_model=list[AccountOut])
async def list_accounts(_: Admin = Depends(current_admin),
                        db: AsyncSession = Depends(get_session)) -> list[AccountOut]:
    res = await db.execute(select(SipAccount).order_by(SipAccount.id))
    accs = list(res.scalars())
    if not accs:
        return []
    ids = [a.id for a in accs]
    res2 = await db.execute(select(Registration).where(Registration.account_id.in_(ids)))
    regs = {r.account_id: r for r in res2.scalars()}
    out: list[AccountOut] = []
    for a in accs:
        out.append(_account_to_out(a, regs.get(a.id)))
    return out


@app.get("/api/accounts/{username}", response_model=AccountOut)
async def get_account(username: str, _: Admin = Depends(current_admin),
                      db: AsyncSession = Depends(get_session)) -> AccountOut:
    acc = await _must_account(db, username)
    res = await db.execute(select(Registration).where(Registration.account_id == acc.id))
    return _account_to_out(acc, res.scalar_one_or_none())


@app.patch("/api/accounts/{username}", response_model=AccountOut)
async def update_account(username: str, payload: AccountUpdate,
                         _: Admin = Depends(current_admin),
                         db: AsyncSession = Depends(get_session)) -> AccountOut:
    acc = await _must_account(db, username)
    if payload.password is not None:
        acc.ha1 = compute_ha1(username, settings.sip_realm, payload.password)
    if payload.display_name is not None:
        acc.display_name = payload.display_name
    if payload.description is not None:
        acc.description = payload.description
    if payload.enabled is not None:
        acc.enabled = payload.enabled
    db.add(acc)
    await db.commit()
    await db.refresh(acc)
    res = await db.execute(select(Registration).where(Registration.account_id == acc.id))
    return _account_to_out(acc, res.scalar_one_or_none())


@app.delete("/api/accounts/{username}", status_code=status.HTTP_204_NO_CONTENT, response_model=None)
async def delete_account(username: str, _: Admin = Depends(current_admin),
                         db: AsyncSession = Depends(get_session)):
    acc = await _must_account(db, username)
    await db.delete(acc)
    await db.commit()


# ============== 消息历史 ==============
@app.get("/api/messages", response_model=list[MessageOut])
async def list_messages(user: Optional[str] = None, limit: int = 100,
                        _: Admin = Depends(current_admin),
                        db: AsyncSession = Depends(get_session)) -> list[MessageOut]:
    stmt = select(Message).order_by(desc(Message.created_at)).limit(min(limit, 500))
    if user:
        stmt = select(Message).where(
            (Message.from_user == user) | (Message.to_user == user)
        ).order_by(desc(Message.created_at)).limit(min(limit, 500))
    res = await db.execute(stmt)
    return [MessageOut.model_validate(r) for r in res.scalars()]


# ============== 主动下发短信 / 语音 URL ==============
@app.post("/api/send_message")
async def send_message(payload: SendMessageReq,
                       _: Admin = Depends(current_admin),
                       db: AsyncSession = Depends(get_session)) -> dict:
    if payload.msg_type not in ("text", "voice"):
        raise HTTPException(400, "msg_type must be text or voice")
    row = Message(
        from_user=payload.from_user,
        to_user=payload.to_user,
        msg_type=payload.msg_type,
        body=payload.body,
        delivered=False,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    # 通过全局 SIP server 实例尝试投递（在 main.py 注入）
    from .runtime import sip_protocol
    if sip_protocol is not None:
        ctype = "application/x-voice-url" if payload.msg_type == "voice" else "text/plain;charset=utf-8"
        await sip_protocol._try_deliver(row.id, payload.from_user, payload.to_user, payload.body, ctype)
    return {"id": row.id, "delivered": row.delivered}


# ============== 语音消息上传/下载 ==============
@app.post("/api/voice/upload")
async def voice_upload(
    owner: str = Form(...),
    to_user: Optional[str] = Form(None),
    file: UploadFile = File(...),
    _: Admin = Depends(current_admin),
    db: AsyncSession = Depends(get_session),
) -> dict:
    """上传语音文件（PCM/WAV/Opus 等）。

    可选 to_user：上传后立即通过 SIP MESSAGE 推送下载 URL 给目标设备。
    """
    data = await file.read(settings.voice_max_bytes + 1)
    if len(data) > settings.voice_max_bytes:
        raise HTTPException(413, "file too large")
    file_id = secrets.token_urlsafe(12)
    ext = (Path(file.filename or "voice.wav").suffix or ".wav").lower()
    storage = settings.voice_dir_path / f"{file_id}{ext}"
    storage.write_bytes(data)
    vf = VoiceFile(
        file_id=file_id,
        owner=owner,
        path=str(storage),
        size_bytes=len(data),
        mime=file.content_type or "audio/wav",
    )
    db.add(vf)
    await db.commit()
    url = f"http://{settings.public_host}:{settings.api_port}/api/voice/{file_id}"

    # 自动推送
    if to_user:
        msg_row = Message(from_user=owner, to_user=to_user, msg_type="voice",
                          body=url, delivered=False)
        db.add(msg_row)
        await db.commit()
        await db.refresh(msg_row)
        from .runtime import sip_protocol
        if sip_protocol is not None:
            await sip_protocol._try_deliver(msg_row.id, owner, to_user, url,
                                             "application/x-voice-url")
    return {"file_id": file_id, "url": url, "size": len(data)}


@app.get("/api/voice/{file_id}")
async def voice_download(file_id: str, db: AsyncSession = Depends(get_session)) -> FileResponse:
    res = await db.execute(select(VoiceFile).where(VoiceFile.file_id == file_id))
    vf = res.scalar_one_or_none()
    if not vf:
        raise HTTPException(404, "not found")
    return FileResponse(vf.path, media_type=vf.mime, filename=Path(vf.path).name)


# ============== Helpers ==============
async def _must_account(db: AsyncSession, username: str) -> SipAccount:
    res = await db.execute(select(SipAccount).where(SipAccount.username == username))
    acc = res.scalar_one_or_none()
    if not acc:
        raise HTTPException(404, "account not found")
    return acc


def _account_to_out(acc: SipAccount, reg: Optional[Registration]) -> AccountOut:
    online = False
    contact = None
    expires_at = None
    if reg and reg.expires_at:
        exp = reg.expires_at
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp > datetime.now(timezone.utc):
            online = True
            contact = reg.contact_uri
            expires_at = exp
    return AccountOut(
        id=acc.id,
        username=acc.username,
        display_name=acc.display_name,
        description=acc.description,
        enabled=acc.enabled,
        online=online,
        contact_uri=contact,
        expires_at=expires_at,
        created_at=acc.created_at,
    )


@app.get("/api/health")
async def health() -> dict:
    return {"status": "ok", "time": datetime.now(timezone.utc).isoformat()}


# ============== 实时通话 ==============
@app.get("/api/calls")
async def list_calls(_: Admin = Depends(current_admin)) -> list[dict]:
    from .runtime import sip_protocol
    if sip_protocol is None:
        return []
    return sip_protocol.list_calls()  # type: ignore[attr-defined]


@app.post("/api/calls/{call_id}/hangup")
async def hangup_call(call_id: str, _: Admin = Depends(current_admin)) -> dict:
    from .runtime import sip_protocol
    if sip_protocol is None:
        raise HTTPException(503, "sip not running")
    ok = await sip_protocol.force_hangup(call_id)  # type: ignore[attr-defined]
    if not ok:
        raise HTTPException(404, "call not found")
    return {"ok": True}


# ============== 静态 Web UI ==============
_WEB_DIR = Path(__file__).parent / "web"
if _WEB_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(_WEB_DIR), html=True), name="web")


@app.get("/")
async def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/ui/")
