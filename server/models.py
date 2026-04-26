"""SQLAlchemy 数据模型。

- Admin：管理员账号
- SipAccount：SIP 设备账号（每台 ESP32-S3 一个）
- Registration：当前在线注册（contact + expires + 来源地址）
- Message：消息历史（文本短信 / 语音消息）
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

# SQLite 只有 INTEGER PRIMARY KEY 才会作为 rowid 自动自增；
# 直接用 BigInteger 会渲染成 BIGINT，导致 INSERT 时 id 为 NULL 而失败。
# 用 with_variant 在 SQLite 下回退为 Integer，其它数据库仍是 BIGINT。
BigIntPK = BigInteger().with_variant(Integer(), "sqlite")


class Base(DeclarativeBase):
    pass


class Admin(Base):
    __tablename__ = "admins"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_super: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SipAccount(Base):
    """SIP 用户/设备账号。

    密码以明文存储是因为 SIP Digest（RFC 2617）需要服务器持有共享密钥
    才能计算 HA1。生产环境推荐：
      - 使用单独的加密列，或
      - 改为预先存储 HA1 = MD5(user:realm:pass) 而非明文。
    本实现采用第二种：仅保存 ha1，不保存明文。
    """

    __tablename__ = "sip_accounts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    realm: Mapped[str] = mapped_column(String(128), nullable=False)
    ha1: Mapped[str] = mapped_column(String(64), nullable=False)  # MD5(user:realm:password)
    display_name: Mapped[Optional[str]] = mapped_column(String(128))
    description: Mapped[Optional[str]] = mapped_column(String(255))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    registration: Mapped[Optional["Registration"]] = relationship(
        back_populates="account", uselist=False, cascade="all, delete-orphan"
    )


class Registration(Base):
    __tablename__ = "registrations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    account_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("sip_accounts.id", ondelete="CASCADE"), unique=True, nullable=False
    )
    contact_uri: Mapped[str] = mapped_column(String(255), nullable=False)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False)
    source_port: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    user_agent: Mapped[Optional[str]] = mapped_column(String(255))
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    account: Mapped[SipAccount] = relationship(back_populates="registration")


class Message(Base):
    """消息历史（SIP MESSAGE / 语音消息）。

    生产-消费模型保证投递可靠：
      - status: pending(已接收待投递) / delivered(对端已签收 200 OK) /
                read(对端已读) / failed(超过最大重试)
      - delivered/delivered_at 保留兼容字段，与 status 同步
      - attempts/last_attempt_at 用于重试调度
    """

    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    from_user: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    to_user: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    msg_type: Mapped[str] = mapped_column(String(16), nullable=False)  # text / voice
    body: Mapped[str] = mapped_column(Text, nullable=False)            # 文本内容或语音 URL
    delivered: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(
        String(16), default="pending", nullable=False, index=True
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    read_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    last_attempt_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class VoiceFile(Base):
    __tablename__ = "voice_files"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    file_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(64), nullable=False)
    path: Mapped[str] = mapped_column(String(512), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime: Mapped[str] = mapped_column(String(64), default="audio/wav")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Friendship(Base):
    """好友关系。

    单行存储一对关系，from_user/to_user 不分先后；
    status: pending(请求中) / accepted(已通过) / blocked(拉黑)。
    """

    __tablename__ = "friendships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    from_user: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    to_user: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="pending")
    note: Mapped[Optional[str]] = mapped_column(String(255))  # 申请附言 / 备注
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    accepted_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))


class InviteToken(Base):
    """好友邀请令牌（用于扫码加好友）。"""

    __tablename__ = "invite_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    token: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    owner: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    note: Mapped[Optional[str]] = mapped_column(String(255))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_by: Mapped[Optional[str]] = mapped_column(String(64))
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

