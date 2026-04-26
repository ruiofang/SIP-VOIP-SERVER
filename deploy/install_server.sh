#!/usr/bin/env bash
# ============================================================
# SIP-VOIP-SERVER 服务端一键部署脚本（裸机 / VPS / 阿里云 ECS）
# 用法:
#   bash deploy/install_server.sh                  # 默认 systemd 模式
#   MODE=docker bash deploy/install_server.sh      # 改用 docker compose
#   MODE=run    bash deploy/install_server.sh      # 仅前台运行（调试）
# 可选环境变量:
#   PUBLIC_HOST=1.2.3.4   对外宣告 IP / 域名（必填，建议写入）
#   SIP_PORT=5060 API_PORT=8000 RTP_MIN=20000 RTP_MAX=20199
#   DATABASE_URL=...      默认 sqlite+aiosqlite:///./sip.db
#   JWT_SECRET=...        默认随机生成
#   ADMIN_DEFAULT_PASS=...默认 admin123（部署后请立刻在 Web UI 修改）
#   APP_DIR=/opt/sip-voip-server  安装目录
# ============================================================
set -euo pipefail

MODE="${MODE:-systemd}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
PUBLIC_HOST="${PUBLIC_HOST:-}"
SIP_PORT="${SIP_PORT:-5060}"
API_PORT="${API_PORT:-8000}"
RTP_MIN="${RTP_MIN:-20000}"
RTP_MAX="${RTP_MAX:-20199}"
DATABASE_URL="${DATABASE_URL:-sqlite+aiosqlite:///./sip.db}"
SIP_REALM="${SIP_REALM:-sip.example.com}"
JWT_SECRET="${JWT_SECRET:-$(head -c 32 /dev/urandom | base64 | tr -d '=+/' | head -c 40)}"
ADMIN_DEFAULT_USER="${ADMIN_DEFAULT_USER:-admin}"
ADMIN_DEFAULT_PASS="${ADMIN_DEFAULT_PASS:-admin123}"
LOG_LEVEL="${LOG_LEVEL:-INFO}"
SERVICE_USER="${SERVICE_USER:-sipvoip}"

cd "$APP_DIR"
echo "[*] APP_DIR=$APP_DIR  MODE=$MODE"

if [[ -z "$PUBLIC_HOST" ]]; then
  PUBLIC_HOST="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$PUBLIC_HOST" ]] && PUBLIC_HOST="127.0.0.1"
  echo "[!] PUBLIC_HOST 未设置, 自动使用 $PUBLIC_HOST"
fi

# ---------- 写入 .env ----------
ENV_FILE="$APP_DIR/.env"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "[*] 生成 $ENV_FILE"
  cat > "$ENV_FILE" <<EOF
SIP_HOST=0.0.0.0
SIP_PORT=$SIP_PORT
API_HOST=0.0.0.0
API_PORT=$API_PORT
PUBLIC_HOST=$PUBLIC_HOST
PUBLIC_SIP_PORT=$SIP_PORT
RTP_PORT_MIN=$RTP_MIN
RTP_PORT_MAX=$RTP_MAX
DATABASE_URL=$DATABASE_URL
JWT_SECRET=$JWT_SECRET
SIP_REALM=$SIP_REALM
ADMIN_DEFAULT_USER=$ADMIN_DEFAULT_USER
ADMIN_DEFAULT_PASS=$ADMIN_DEFAULT_PASS
VOICE_STORAGE_DIR=$APP_DIR/voice_storage
VOICE_MAX_BYTES=2097152
LOG_LEVEL=$LOG_LEVEL
EOF
else
  echo "[=] $ENV_FILE 已存在, 保留不覆盖"
fi
mkdir -p "$APP_DIR/voice_storage"

# ---------- Docker 模式 ----------
if [[ "$MODE" == "docker" ]]; then
  command -v docker >/dev/null || { echo "需要 docker"; exit 1; }
  if docker compose version >/dev/null 2>&1; then DC="docker compose"
  elif command -v docker-compose >/dev/null; then DC="docker-compose"
  else echo "需要 docker compose"; exit 1; fi
  cd "$APP_DIR/deploy"
  $DC up -d --build
  echo "[OK] docker 启动完成: $DC ps"
  $DC ps
  exit 0
fi

# ---------- 通用: Python venv ----------
PYBIN="${PYBIN:-python3}"
command -v "$PYBIN" >/dev/null || { echo "需要 python3"; exit 1; }
VENV="$APP_DIR/.venv"
if [[ ! -d "$VENV" ]]; then
  echo "[*] 创建 venv -> $VENV"
  "$PYBIN" -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
"$VENV/bin/pip" install -r "$APP_DIR/server/requirements.txt"
# passlib 与 bcrypt>=4.1 不兼容 (会抛 'password cannot be longer than 72 bytes')
"$VENV/bin/pip" install "bcrypt<4.1"

# ---------- run 模式：前台 ----------
if [[ "$MODE" == "run" ]]; then
  echo "[*] 前台启动 (Ctrl-C 退出)"
  cd "$APP_DIR"
  set -a; source "$ENV_FILE"; set +a
  exec "$VENV/bin/python" -m server.main
fi

# ---------- systemd 模式 ----------
if [[ "$MODE" != "systemd" ]]; then
  echo "未知 MODE=$MODE (支持: systemd/docker/run)"; exit 1
fi

if [[ $EUID -ne 0 ]]; then
  echo "[!] systemd 模式需要 root, 请使用: sudo MODE=systemd bash $0"; exit 1
fi

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home "$APP_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/voice_storage" "$ENV_FILE" || true
[[ -f "$APP_DIR/sip.db" ]] && chown "$SERVICE_USER:$SERVICE_USER" "$APP_DIR/sip.db" || true

UNIT=/etc/systemd/system/sip-voip-server.service
cat > "$UNIT" <<EOF
[Unit]
Description=SIP-VOIP-SERVER (RUIO)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
ExecStart=$VENV/bin/python -m server.main
Restart=on-failure
RestartSec=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now sip-voip-server.service
sleep 2
systemctl --no-pager --full status sip-voip-server.service || true

cat <<EOF

================ 部署完成 ================
APP_DIR       : $APP_DIR
PUBLIC_HOST   : $PUBLIC_HOST
SIP           : udp/$SIP_PORT
API / Web UI  : http://$PUBLIC_HOST:$API_PORT/ui/
RTP 端口段    : udp/$RTP_MIN-$RTP_MAX
管理员账号    : $ADMIN_DEFAULT_USER / $ADMIN_DEFAULT_PASS  ⚠ 立刻修改

常用命令:
  systemctl status sip-voip-server
  journalctl -u sip-voip-server -f
  systemctl restart sip-voip-server

阿里云安全组放行: udp/$SIP_PORT, tcp/$API_PORT, udp/$RTP_MIN-$RTP_MAX
==========================================
EOF
