# SIP-VOIP-SERVER

一个可部署到阿里云的轻量级 SIP/VoIP 服务，专为 **ESP32-S3 小智** 等 IoT 设备接入而设计。

## 功能

- ✅ SIP REGISTER（RFC 3261，带 MD5 Digest 鉴权）
- ✅ SIP MESSAGE（RFC 3428，文本短信，支持离线存储）
- ✅ **可靠消息投递**：生产-消费模型，支持发送方追踪 `已送达 / 已读 / 失败`
  状态（`X-Message-ID` + `application/x-message-status+json` 回执），离线消息
  在对端上线后自动重投，未确认者按指数退避重试至上限再标记 `failed`
- ✅ **实时通话（B2BUA + RTP 媒体中继）**：INVITE / ACK / BYE / CANCEL / re-INVITE，
  自动 SDP 改写，UDP 端口对中继 RTP+RTCP，symmetric RTP 学习对端地址（NAT 友好）
- ✅ SIP OPTIONS（保活）
- ✅ 语音消息：HTTP 上传 + 通过 SIP MESSAGE 推送下载链接
- ✅ **Web 管理界面**（`/ui/`）：登录、设备账号 CRUD、在线状态、实时通话监控
  + 强制挂断、消息历史、发送短信 / 上传语音、好友关系管理
- ✅ **好友系统**：用户互加 / 服务端审核 / 二维码扫码加好友（一次性 token）
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
├── client_pc/
│   ├── sip_client.py        # PC 端纯 Python 测试客户端
│   ├── rtp.py / g711.py     # RTP + G.711 编解码
│   ├── requirements.txt
│   └── README.md
├── deploy/
│   ├── docker-compose.yml
│   ├── Dockerfile
│   ├── nginx.conf
│   └── aliyun_deploy.md     # 阿里云部署指引
├── .env.example
└── README.md
```

## 一键部署 / 启动

服务端（裸机 / VPS / 阿里云 ECS）：

```bash
# systemd 模式（推荐生产）
sudo PUBLIC_HOST=your.public.ip MODE=systemd bash deploy/install_server.sh

# Docker Compose 模式
MODE=docker bash deploy/install_server.sh

# 前台调试模式
MODE=run bash deploy/install_server.sh
```

脚本会自动建 venv、装依赖（含 `bcrypt<4.1` 兼容修复）、生成 `.env`（随机
`JWT_SECRET`），并注册 systemd 服务；Docker 模式直接调用
[deploy/docker-compose.yml](deploy/docker-compose.yml)。常用环境变量：
`SIP_PORT / API_PORT / RTP_MIN / RTP_MAX / DATABASE_URL / JWT_SECRET /
ADMIN_DEFAULT_PASS`。

PC 客户端：

```bash
SERVER=1.2.3.4 USER=1001 PASSWORD=secret123 \
  API_BASE=http://1.2.3.4:8000 \
  bash client_pc/run_client.sh
```

不带变量则脚本交互问询；自动建 venv 并安装 [client_pc/requirements.txt](client_pc/requirements.txt)。

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

## PC 测试客户端

见 [client_pc/README.md](client_pc/README.md) — 纯 Python 实现，支持 REGISTER / MESSAGE /
INVITE 真实通话 + RTP 音频，并可调用管理后台 REST API，方便端到端测试。

## 好友系统

支持三种加好友方式，可在客户端或服务端管理界面操作：

| 流程 | 接口 | 说明 |
| --- | --- | --- |
| 申请 + 审核 | `POST /api/friends/request` → `POST /api/friends/{fid}/accept` | 发起方提交申请（pending），接收方在好友列表里通过/拒绝 |
| 二维码扫码 | `POST /api/friends/invite` 生成 token → `POST /api/friends/scan` | 一次性 token，默认 10 分钟过期，扫码后立即互为好友 |
| 管理员代加 | `POST /api/admin/friends` | 管理员可绕过审核直接建立关系，亦可在 Web `好友关系` 标签页查看/删除全部关系 |

用户级 JWT：客户端使用 `POST /api/user/login`（用户名 + SIP 注册密码）登录获取令牌，
和管理员令牌区分（JWT 里 `kind` 字段为 `user` / `admin`）。

PC 客户端 REPL 命令：`friends`、`friend-add`、`friend-accept`、`qr [ttl] [note]`、
`scan <token>`、`scan-uri <sipfriend://...>`，更多见 [client_pc/README.md](client_pc/README.md)。

## 作者

RUIO

## 许可证

本项目基于 [MIT License](LICENSE) 开源发布，详见 [LICENSE](LICENSE) 文件。

