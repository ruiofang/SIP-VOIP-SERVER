# SIP-VOIP-SERVER · PC 测试客户端

一个**纯 Python** 实现的 SIP/VoIP 客户端，零外部 SIP 库，方便在 PC 端对服务端做端到端测试。

## 功能

- ✅ SIP REGISTER（带 MD5 Digest 鉴权，自动定时刷新）
- ✅ 发送 SIP MESSAGE（文本短信）/ 接收 MESSAGE 并自动回 200
- ✅ **可靠投递**：发送方收到服务端 `X-Message-ID`，并在对端收到 / 已读
  时收到状态推送（`[STATUS msg #N -> 1002] 已送达 / 已读`）
- ✅ SIP OPTIONS 保活
- ✅ **拨打 / 接听语音通话**（INVITE / 100 Trying / 180 Ringing / 200 OK / ACK / BYE / CANCEL）
- ✅ RTP 音频收发（G.711 PCMU/PCMA 编解码，麦克风→对端，对端→扬声器）
- ✅ 通过管理后台 REST API 上传语音文件、发送短信、查看通话/账号
- ✅ 命令行交互式 REPL（注册、call、hangup、msg、who 等命令）
- ✅ 支持脚本化（无音频依赖时自动降级为静默 RTP，可作为压力/集成测试）

> 不依赖 PJSIP / Linphone / Twinkle 等 SDK。仅可选地依赖 `sounddevice` + `numpy` 进行实时音频；
> 不安装时仍可注册、收发短信、建立呼叫（仅不出声）。

## 安装

```bash
cd client_pc
pip install -r requirements.txt
```

如果只做信令/短信测试，可以只装 `requests`，跳过 `sounddevice`。

Linux 上 `sounddevice` 需要 PortAudio：

```bash
sudo apt-get install -y libportaudio2
```

## 快速开始

最小用法（只测 SIP，不需要管理员账号）：

```bash
python sip_client.py \
  --server 127.0.0.1 --sip-port 5060 \
  --user 1001 --password secret123 \
  --realm sip.example.com
```

可选：附带管理后台凭据，REPL 即可调用 `who` / `calls` / `hist` / `upload` /
`api-msg` / `rest-hangup` 这些走 REST API 的命令（等价于在浏览器里以 admin
登录 Web 管理界面）。**不带这些参数时这几条命令不可用，但其它 SIP 功能完全不受影响。**

```bash
python sip_client.py \
  --server 127.0.0.1 --user 1001 --password secret123 \
  --realm sip.example.com \
  --api-base http://127.0.0.1:8000 \
  --admin-user admin --admin-password admin123
```

进入 REPL 后：

```
sip> register             # 注册（启动后会自动注册一次）
sip> who                  # 列出所有账号 + 在线状态（走 REST API）
sip> msg 1002 你好         # 发文本短信，返回 OK msgid=N
sip> read 1002 N          # 手动给 1002 的消息 #N 发已读回执（默认已自动）
sip> call 1002            # 拨打
sip> hangup               # 挂断当前呼叫
sip> answer               # 接听来电
sip> reject               # 拒接来电
sip> status               # 查看当前 SIP/RTP 统计（排查无音频时很有用）
sip> calls                # 查看服务端实时通话
sip> upload demo.wav 1002 # 上传语音并自动推送给 1002
sip> quit
```

### 好友相关命令

REPL 通过 `--api-base` 自动用 SIP 账号登录用户级 API（无需 admin 凭据）：

```
sip> friends                          # 列出我的好友/申请
sip> friend-add 1002 hello            # 向 1002 发申请（pending）
sip> friend-accept <fid>              # 通过对方申请
sip> friend-reject <fid>              # 拒绝
sip> friend-del <fid>                 # 删除好友
sip> qr 600 add-me                    # 生成 600 秒邀请，并打印 ASCII 二维码
sip> invites                          # 查看历史邀请
sip> scan <token>                     # 扫描对方 token 立即互加
sip> scan-uri sipfriend://realm/user?token=xxxx
```

二维码渲染需要 `qrcode` 包（已加入 `requirements.txt`，缺失时会回退为纯文本输出）。

## 主要参数

| 参数 | 说明 | 默认 |
|---|---|---|
| `--server` | SIP 服务器地址（公网 IP / 域名） | 必填 |
| `--sip-port` | SIP 端口 | `5060` |
| `--local-port` | 本地 UDP 端口（0=自动） | `0` |
| `--user` / `--password` | SIP 账号 | 必填 |
| `--realm` | SIP realm（与服务端 `SIP_REALM` 一致） | `sip.example.com` |
| `--rtp-port` | 本地 RTP 端口（0=自动，偶数） | `0` |
| `--local-ip` | 强制写入 SDP/Contact 的本机地址，适合多网卡/VPN/直连媒体排障 | 自动探测 |
| `--no-audio` | 不打开声卡，纯静默 RTP | 关闭 |
| `--codec` | `pcmu` / `pcma` | `pcmu` |
| `--api-base` | 管理后台 URL（用于 REST 测试） | 空=不启用 |
| `--admin-user` / `--admin-password` | 管理员凭据 | 空 |
| `--auto-answer` | 自动接听来电（适合做被叫机器） | 关闭 |
| `--no-auto-read` | 收到消息后**不**自动回送已读回执（默认自动） | 关闭 |
| `--script` | 从文件按行执行命令后退出 | 空 |

## 脚本化测试

```bash
cat > /tmp/test.txt <<'EOF'
register
sleep 1
msg 1002 hello-from-script
call 1002
sleep 5
hangup
quit
EOF

python sip_client.py --user 1001 --password secret123 \
  --server 127.0.0.1 --realm sip.example.com \
  --no-audio --script /tmp/test.txt
```

## 设计要点

- **信令栈**：`asyncio.DatagramProtocol` 收发 UDP；逐行解析；维持 dialog（Call-ID / tags / Via / CSeq / Route / Contact）。
- **Digest 鉴权**：收到 `401 / 407` 时自动用 HA1 = MD5(user:realm:password) 重发；支持 qop=auth。
- **NAT**：在 Via 加 `rport`，从响应里学习公网映射；Contact 中使用本地地址（服务端会重写）。
- **RTP**：UDP 偶数端口，20 ms 帧，G.711 8 kHz 单声道；时间戳 +160；序号自增；SSRC 随机。
- **音频**：`sounddevice.InputStream/OutputStream` 16-bit PCM，
  `audioop.lin2ulaw` / `lin2alaw` 与 `ulaw2lin` / `alaw2lin` 编解码（标准库自带）。
- **REST**：`requests` 同步访问后台，登录获取 JWT 后调用 `/api/...`，与浏览器 UI 等价。

### 无音频排查

- 通话显示 `200 OK 通话已建立` 后，客户端会在数秒内自动检查是否收到 RTP；若仍未收包，会提示执行 `status` 并检查本机 UDP/防火墙/安全组。
- `status` 里如果 `pkts_sent` 持续增长但 `pkts_recv` 一直为 `0`，通常说明媒体回程没有到达本机。
- 多网卡、VPN 或未经过服务器中继的直连场景，可尝试显式指定 `--local-ip`。

## 已知限制

- 不实现 SRTP / TLS / SIP-over-WebSocket。
- 仅 G.711 编解码（与 ESP32 端默认一致）。
- 单一活跃通话；同时来电会被自动 486 Busy。
