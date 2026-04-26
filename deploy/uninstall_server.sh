#!/usr/bin/env bash
# ============================================================
# SIP-VOIP-SERVER 卸载脚本
# 用法:
#   sudo bash deploy/uninstall_server.sh                    # 卸载 systemd 服务（保留数据/.env/venv）
#   sudo PURGE=1 bash deploy/uninstall_server.sh            # 同时清除 .venv / sip.db / voice_storage / .env / 日志
#   MODE=docker bash deploy/uninstall_server.sh             # 停止并移除 docker compose 栈
#   MODE=docker PURGE=1 bash deploy/uninstall_server.sh     # 同上 + 删除卷与构建镜像
#
# 可选环境变量:
#   APP_DIR=/opt/sip-voip-server   安装目录（默认: 脚本所在仓库根目录）
#   SERVICE_USER=sipvoip           安装时使用的系统用户；PURGE=1 且为系统用户时会被删除
#   KEEP_USER=1                    PURGE 时保留 SERVICE_USER 不删除
# ============================================================
set -euo pipefail

MODE="${MODE:-systemd}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
PURGE="${PURGE:-0}"
SERVICE_NAME="sip-voip-server"
UNIT="/etc/systemd/system/${SERVICE_NAME}.service"

echo "[*] APP_DIR=$APP_DIR  MODE=$MODE  PURGE=$PURGE"

confirm_purge() {
  [[ "$PURGE" != "1" ]] && return
  echo "[!] PURGE=1 将删除以下内容（如存在）:"
  echo "    - $APP_DIR/.venv"
  echo "    - $APP_DIR/.env"
  echo "    - $APP_DIR/sip.db  $APP_DIR/sip.db-shm  $APP_DIR/sip.db-wal"
  echo "    - $APP_DIR/voice_storage/"
  echo "    - $APP_DIR/logs/  $APP_DIR/*.log"
  if [[ -t 0 && -z "${YES:-}" ]]; then
    read -r -p "确认继续? [y/N] " ans
    [[ "$ans" =~ ^[yY]$ ]] || { echo "已取消"; exit 1; }
  fi
}

purge_data() {
  [[ "$PURGE" != "1" ]] && return
  echo "[*] 清理数据文件"
  rm -rf "$APP_DIR/.venv" \
         "$APP_DIR/voice_storage" \
         "$APP_DIR/logs"
  rm -f  "$APP_DIR/.env" \
         "$APP_DIR/sip.db" "$APP_DIR/sip.db-shm" "$APP_DIR/sip.db-wal" \
         "$APP_DIR"/*.log 2>/dev/null || true
}

# ---------- Docker 模式 ----------
if [[ "$MODE" == "docker" ]]; then
  command -v docker >/dev/null || { echo "需要 docker"; exit 1; }
  if docker compose version >/dev/null 2>&1; then DC="docker compose"
  elif command -v docker-compose >/dev/null; then DC="docker-compose"
  else echo "需要 docker compose"; exit 1; fi

  confirm_purge
  cd "$APP_DIR/deploy"
  if [[ "$PURGE" == "1" ]]; then
    $DC down -v --rmi local --remove-orphans || true
  else
    $DC down --remove-orphans || true
  fi
  cd "$APP_DIR"
  purge_data
  echo "[OK] docker 栈已停止/移除"
  exit 0
fi

# ---------- systemd / run 模式 ----------
if [[ "$MODE" != "systemd" && "$MODE" != "run" ]]; then
  echo "未知 MODE=$MODE (支持: systemd/docker/run)"; exit 1
fi

if [[ "$MODE" == "systemd" ]]; then
  if [[ $EUID -ne 0 ]]; then
    echo "[!] systemd 模式需要 root, 请使用: sudo bash $0"; exit 1
  fi
  confirm_purge
  if systemctl list-unit-files | grep -q "^${SERVICE_NAME}.service"; then
    echo "[*] 停止并禁用 $SERVICE_NAME"
    systemctl stop "$SERVICE_NAME" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME" 2>/dev/null || true
  fi
  if [[ -f "$UNIT" ]]; then
    rm -f "$UNIT"
    systemctl daemon-reload
    systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
    echo "[*] 已删除 $UNIT"
  else
    echo "[=] $UNIT 不存在, 跳过"
  fi
  if [[ "$PURGE" == "1" ]]; then
    journalctl --rotate 2>/dev/null || true
    journalctl --vacuum-time=1s --unit="$SERVICE_NAME" 2>/dev/null || true
  fi
else
  confirm_purge
  # run 模式: 尝试结束可能残留的前台进程
  pkill -f "server\.main" 2>/dev/null || true
fi

purge_data

# ---------- PURGE 时考虑删除系统用户 ----------
if [[ "$PURGE" == "1" && "${KEEP_USER:-0}" != "1" ]]; then
  SERVICE_USER="${SERVICE_USER:-sipvoip}"
  if id -u "$SERVICE_USER" >/dev/null 2>&1; then
    # 仅删除由 install_server.sh 创建的系统用户 (sipvoip), 不动普通登录用户
    if [[ "$SERVICE_USER" == "sipvoip" ]]; then
      echo "[*] 删除系统用户 $SERVICE_USER"
      userdel "$SERVICE_USER" 2>/dev/null || true
    else
      echo "[=] 跳过删除非默认用户 $SERVICE_USER (设置 SERVICE_USER=sipvoip 强制删)"
    fi
  fi
fi

cat <<EOF

================ 卸载完成 ================
模式          : $MODE
APP_DIR       : $APP_DIR
PURGE         : $PURGE  (1=已清空数据/venv/.env)

如需彻底删除安装目录:
  rm -rf "$APP_DIR"

阿里云安全组中放行的 SIP/RTP/API 端口请按需手动回收。
==========================================
EOF
