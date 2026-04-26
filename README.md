# SIP-VOIP-SERVER

一个可部署到阿里云的轻量级 SIP/VoIP 服务，专为 **ESP32-S3 小智** 等 IoT 设备接入而设计。

## 功能

- ✅ SIP REGISTER（RFC 3261，带 MD5 Digest 鉴权）
- ✅ SIP MESSAGE（RFC 3428，文本短信，支持离线存储）
- ✅ **实时通话（B2BUA + RTP 媒体中继）**：INVITE / ACK / BYE / CANCEL / re-INVITE，
  自动 SDP 改写，UDP 端口对中继 RTP+RTCP，symmetric RTP 学习对端地址（NAT 友好）
- ✅ SIP OPTIONS（保活）
- ✅ 语音消息：HTTP 上传 + 通过 SIP MESSAGE 推送下载链接
- ✅ **Web 管理界面**（`/ui/`）：登录、设备账号 CRUD、在线状态、实时通话监控
  + 强制挂断、消息历史、发送短信 / 上传语音
- ✅ MySQL / SQLite 持久化（阿里云 RDS 直连）
- ✅ Docker Compose 一键部署
- ✅ ESP-IDF C 客户端示例

## 目录结构

```
.
├── server/
│   ├── sip_server.py        # SIP UDP 信令服务器（asyncio）
│   ├── api.py               # FastAPI 管理后台 + 语音上传
│   ├── models.py            # SQLAlchemy 数据模型
│   ├── auth.py              # JWT + SIP Digest 工具
│   ├── db.py                # 数据库连接
│   ├── config.py            # 配置加载
│   ├── main.py              # 进程入口（同时启动 SIP + API）
│   └── requirements.txt
├── client_esp32/
│   ├── main/sip_client.c    # ESP32-S3 SIP 客户端示例
│   └── README.md
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── nginx.conf
│   └── aliyun_deploy.md     # 阿里云部署指引
├── .env.example
└── README.md
```

## 快速开始（本地）

```bash
cp .env.example .env
cd server
pip install -r requirements.txt
python main.py
```

服务端口：
- `5060/udp` — SIP
- `8000/tcp` — 管理后台 + 语音上传 HTTP API
- `20000-20199/udp` — RTP 媒体中继（可在 `.env` 中调整）

打开浏览器访问 `http://<host>:8000/ui/` 进入 Web 管理界面。

默认管理员账号：`admin / admin123`（首次启动自动创建，请尽快修改）

## 阿里云部署

见 [deploy/aliyun_deploy.md](deploy/aliyun_deploy.md)

## ESP32-S3 接入

见 [client_esp32/README.md](client_esp32/README.md)
