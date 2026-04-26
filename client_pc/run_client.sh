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
set -eo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

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
  [[ -f "$CONFIG_FILE" ]] || die "配置文件尚未创建: $CONFIG_FILE"
  exec "${EDITOR:-vi}" "$CONFIG_FILE"
fi

# 加载已存在的配置：环境变量优先，配置文件作为缺省
if [[ -f "$CONFIG_FILE" && "$RECONFIG" != "1" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$CONFIG_FILE"; set +a
fi

# ---------- venv ----------
PYBIN="${PYBIN:-python3}"
command -v "$PYBIN" >/dev/null || die "缺少 python3，请先安装: sudo apt-get install -y python3"

VENV="$HERE/.venv"

apt_install_venv() {
  command -v apt-get >/dev/null || return 1
  log "尝试安装 python3-venv / python3-pip (需要 sudo)"
  if [[ $EUID -eq 0 ]]; then
    apt-get update -y && apt-get install -y python3-venv python3-pip
  else
    sudo apt-get update -y && sudo apt-get install -y python3-venv python3-pip
  fi
}

ensure_venv() {
  if [[ -x "$VENV/bin/pip" ]]; then return 0; fi
  log "创建 venv -> $VENV"
  rm -rf "$VENV"
  if ! "$PYBIN" -m venv "$VENV" 2>/tmp/venv_err; then
    cat /tmp/venv_err >&2
    if grep -qi 'ensurepip\|python3-venv' /tmp/venv_err; then
      apt_install_venv || die "venv 创建失败，请手动: sudo apt-get install -y python3-venv python3-pip"
      "$PYBIN" -m venv "$VENV" || die "venv 创建仍失败，请手动排查"
    else
      die "venv 创建失败，请检查 python3 安装"
    fi
  fi
  if [[ ! -x "$VENV/bin/pip" ]]; then
    "$VENV/bin/python" -m ensurepip --upgrade || {
      apt_install_venv || true
      "$VENV/bin/python" -m ensurepip --upgrade || die "venv 内 pip 不可用"
    }
  fi
}
ensure_venv

PIP="$VENV/bin/pip"
"$PIP" install --upgrade pip wheel >/dev/null 2>&1 || warn "pip/wheel 升级失败 (忽略)"

# 必装：requests（REST API 调用、Digest 等本身用不到，但客户端管理命令依赖）
if ! "$PIP" install -q "requests>=2.31"; then
  die "安装 requests 失败，请检查网络 / 镜像源"
fi

# 选装：音频依赖。缺 libportaudio2 时 pip 仍能装上 wheel，但运行时才会报错；
# 这里只在用户没有显式 NO_AUDIO=1 时尝试，失败不致命。
if [[ "${NO_AUDIO:-0}" != "1" ]]; then
  if ! "$PIP" install -q "sounddevice>=0.4.6" "numpy>=1.26" 2>/tmp/audio_err; then
    warn "音频依赖安装失败 (sounddevice/numpy)，已自动切换到 --no-audio 模式"
    warn "如需音频，请: sudo apt-get install -y libportaudio2 portaudio19-dev"
    NO_AUDIO=1
  fi
fi

# 选装：二维码（缺失时客户端会回退到纯文本输出）
"$PIP" install -q "qrcode>=7.4" >/dev/null 2>&1 || warn "qrcode 安装失败 (忽略，二维码命令将退化为纯文本)"

# ---------- 收集参数 ----------
ask() { local var="$1" prompt="$2" def="${3:-}"
  if [[ -z "${!var:-}" || "$RECONFIG" == "1" ]]; then
    local cur="${!var:-$def}"
    local val
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

[[ -n "${SERVER:-}"   ]] || die "SERVER 未设置"
[[ -n "${USER:-}"     ]] || die "USER 未设置"
[[ -n "${PASSWORD:-}" ]] || die "PASSWORD 未设置"

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
chmod 600 "$CONFIG_FILE" || true
log "配置已保存: $CONFIG_FILE  (下次直接 \`bash run_client.sh\` 即可启动)"

# ---------- 启动 ----------
ARGS=( --server "$SERVER" --sip-port "$SIP_PORT"
       --user "$USER" --password "$PASSWORD"
       --realm "$REALM" --codec "$CODEC" )
[[ -n "${API_BASE:-}" ]]         && ARGS+=( --api-base "$API_BASE" )
[[ "${NO_AUDIO:-0}" == "1" ]]    && ARGS+=( --no-audio )
[[ "${AUTO_ANSWER:-0}" == "1" ]] && ARGS+=( --auto-answer )

log "启动 sip_client.py ..."
# shellcheck disable=SC2086
exec "$VENV/bin/python" "$HERE/sip_client.py" "${ARGS[@]}" ${EXTRA_ARGS:-} ${PASSTHRU[@]+"${PASSTHRU[@]}"}
