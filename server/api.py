"""FastAPI 管理后台 + 语音消息上传/下载 + 主动下发 API。"""
from __future__ import annotations

import logging
import secrets
from datetime import datetime, timezone
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
                   hash_password, verify_password)
from .config import get_settings
from .db import get_session, init_db, session_scope
from .models import Admin, Message, Registration, SipAccount, VoiceFile

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
    created_at: datetime
    delivered_at: Optional[datetime] = None

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


@app.delete("/api/accounts/{username}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(username: str, _: Admin = Depends(current_admin),
                         db: AsyncSession = Depends(get_session)) -> None:
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
    if reg and reg.expires_at and reg.expires_at > datetime.now(timezone.utc):
        online = True
        contact = reg.contact_uri
        expires_at = reg.expires_at
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
