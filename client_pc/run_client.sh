#!/usr/bin/env bash
# ============================================================
# SIP-VOIP-SERVER PC 客户端一键启动脚本
# 用法:
#   bash client_pc/run_client.sh                          # 交互问询
#   SERVER=1.2.3.4 USER=1001 PASSWORD=secret123 \
#     bash client_pc/run_client.sh                        # 静默
# 可选:
#   SIP_PORT=5060 REALM=sip.example.com API_BASE=http://1.2.3.4:8000
#   CODEC=pcmu NO_AUDIO=1 AUTO_ANSWER=1
#   EXTRA_ARGS="--script /tmp/cmds.txt"
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

PYBIN="${PYBIN:-python3}"
command -v "$PYBIN" >/dev/null || { echo "需要 python3"; exit 1; }

VENV="$HERE/.venv"
if [[ ! -d "$VENV" ]]; then
  echo "[*] 创建 venv -> $VENV"
  "$PYBIN" -m venv "$VENV"
fi
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
"$VENV/bin/pip" install -r "$HERE/requirements.txt"

ask() { local var="$1" prompt="$2" def="${3:-}"
  if [[ -z "${!var:-}" ]]; then
    if [[ -n "$def" ]]; then read -rp "$prompt [$def]: " val; val="${val:-$def}"
    else read -rp "$prompt: " val; fi
    printf -v "$var" '%s' "$val"
  fi
}

ask SERVER   "SIP 服务器地址"
ask SIP_PORT "SIP 端口"     "5060"
ask USER     "SIP 用户名"
ask PASSWORD "SIP 密码"
ask REALM    "SIP realm"    "sip.example.com"
ask API_BASE "管理 API URL (可空, 启用好友/REST 命令)" ""
ask CODEC    "编解码 pcmu/pcma" "pcmu"

ARGS=( --server "$SERVER" --sip-port "$SIP_PORT"
       --user "$USER" --password "$PASSWORD"
       --realm "$REALM" --codec "$CODEC" )
[[ -n "$API_BASE" ]]      && ARGS+=( --api-base "$API_BASE" )
[[ "${NO_AUDIO:-0}" == "1" ]]    && ARGS+=( --no-audio )
[[ "${AUTO_ANSWER:-0}" == "1" ]] && ARGS+=( --auto-answer )

# shellcheck disable=SC2086
exec "$VENV/bin/python" "$HERE/sip_client.py" "${ARGS[@]}" ${EXTRA_ARGS:-}
