#!/usr/bin/env bash
# ============================================================
# SIP-VOIP-SERVER PC 客户端一键启动脚本
# 用法:
#   bash client_pc/run_client.sh                # 首次会交互问询并保存配置；之后直接启动
#   bash client_pc/run_client.sh --reconfig     # 强制重新交互输入
#   bash client_pc/run_client.sh --edit         # 用 $EDITOR 打开配置文件
#   SERVER=1.2.3.4 USER=1001 PASSWORD=secret123 \
#     bash client_pc/run_client.sh              # 环境变量临时覆盖
#
# 可选环境变量:
#   SIP_PORT REALM API_BASE CODEC NO_AUDIO AUTO_ANSWER EXTRA_ARGS
#   CONFIG_FILE   配置文件路径 (默认 ~/.config/sip-voip-client/config.env)
# ============================================================
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# ---------- 解析 CLI 选项 ----------
RECONFIG=0
EDIT_ONLY=0
PASSTHRU=()
for arg in "$@"; do
  case "$arg" in
    --reconfig) RECONFIG=1 ;;
    --edit)     EDIT_ONLY=1 ;;
    -h|--help)
      sed -n '2,15p' "$0"; exit 0 ;;
    *) PASSTHRU+=("$arg") ;;
  esac
done

# ---------- 配置文件 ----------
CONFIG_FILE="${CONFIG_FILE:-${XDG_CONFIG_HOME:-$HOME/.config}/sip-voip-client/config.env}"
mkdir -p "$(dirname "$CONFIG_FILE")"

if [[ "$EDIT_ONLY" == "1" ]]; then
  [[ -f "$CONFIG_FILE" ]] || { echo "配置文件尚未创建: $CONFIG_FILE"; exit 1; }
  exec "${EDITOR:-vi}" "$CONFIG_FILE"
fi

# 加载已存在的配置：环境变量优先，配置文件作为缺省
if [[ -f "$CONFIG_FILE" && "$RECONFIG" != "1" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$CONFIG_FILE"; set +a
fi

# ---------- venv ----------
PYBIN="${PYBIN:-python3}"
command -v "$PYBIN" >/dev/null || { echo "需要 python3"; exit 1; }
VENV="$HERE/.venv"
ensure_venv() {
  if [[ -x "$VENV/bin/pip" ]]; then return 0; fi
  echo "[*] 创建/修复 venv -> $VENV"
  rm -rf "$VENV"
  if ! "$PYBIN" -m venv "$VENV" 2>/tmp/venv_err; then
    cat /tmp/venv_err
    echo "[!] 请先安装: sudo apt-get install -y python3-venv python3-pip"; exit 1
  fi
  [[ -x "$VENV/bin/pip" ]] || "$VENV/bin/python" -m ensurepip --upgrade
}
ensure_venv
"$VENV/bin/pip" install --upgrade pip wheel >/dev/null
"$VENV/bin/pip" install -r "$HERE/requirements.txt" >/dev/null

# ---------- 收集参数 ----------
ask() { local var="$1" prompt="$2" def="${3:-}"
  if [[ -z "${!var:-}" || "$RECONFIG" == "1" ]]; then
    local cur="${!var:-$def}"
    if [[ -n "$cur" ]]; then read -rp "$prompt [$cur]: " val; val="${val:-$cur}"
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

# ---------- 写回配置文件（密码明文，注意权限）----------
TMP_CFG="$(mktemp)"
{
  echo "# SIP-VOIP-SERVER PC 客户端配置 (由 run_client.sh 自动生成/更新)"
  echo "# 修改本文件或运行 \`run_client.sh --reconfig\` 重新设置。"
  echo "# 密码以明文保存，文件权限已限制为 600。"
  for k in SERVER SIP_PORT USER PASSWORD REALM API_BASE CODEC \
           NO_AUDIO AUTO_ANSWER EXTRA_ARGS; do
    v="${!k:-}"
    [[ -z "$v" ]] && continue
    printf '%s=%q\n' "$k" "$v"
  done
} > "$TMP_CFG"
mv "$TMP_CFG" "$CONFIG_FILE"
chmod 600 "$CONFIG_FILE"
echo "[*] 配置已保存: $CONFIG_FILE  (下次直接 \`bash run_client.sh\` 即可启动)"

# ---------- 启动 ----------
ARGS=( --server "$SERVER" --sip-port "$SIP_PORT"
       --user "$USER" --password "$PASSWORD"
       --realm "$REALM" --codec "$CODEC" )
[[ -n "${API_BASE:-}" ]]         && ARGS+=( --api-base "$API_BASE" )
[[ "${NO_AUDIO:-0}" == "1" ]]    && ARGS+=( --no-audio )
[[ "${AUTO_ANSWER:-0}" == "1" ]] && ARGS+=( --auto-answer )

# shellcheck disable=SC2086
exec "$VENV/bin/python" "$HERE/sip_client.py" "${ARGS[@]}" ${EXTRA_ARGS:-} "${PASSTHRU[@]}"
