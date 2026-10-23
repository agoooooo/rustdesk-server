#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
DATA_DIR="${DATA_DIR:-$ROOT_DIR/data}"
RUN_DIR="$DATA_DIR/run"
HBBS="$ROOT_DIR/target/debug/hbbs"
HBBR="$ROOT_DIR/target/debug/hbbr"
BIND_ADDRESS="${BIND_ADDRESS:-0.0.0.0}"

discover_server_addr() {
    local address=""
    if command -v ip >/dev/null 2>&1; then
        address="$(ip -4 -o addr show scope global 2>/dev/null | awk '{
            split($4, parts, "/")
            ip = parts[1]
            if (ip ~ /^10\./ || ip ~ /^192\.168\./ || ip ~ /^172\.(1[6-9]|2[0-9]|3[01])\./) {
                print ip
                exit
            }
        }')"
    fi
    if [[ -z "$address" ]] && command -v ip >/dev/null 2>&1; then
        address="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{
            for (i = 1; i <= NF; i++) {
                if ($i == "src") {
                    print $(i + 1)
                    exit
                }
            }
        }')"
    fi
    if [[ -z "$address" ]] && command -v hostname >/dev/null 2>&1; then
        address="$(hostname -I 2>/dev/null | awk '{print $1}')"
    fi
    printf '%s' "${address:-127.0.0.1}"
}

SERVER_ADDR="${SERVER_ADDR:-$(discover_server_addr)}"

pid_file() {
    printf '%s/%s.pid' "$RUN_DIR" "$1"
}

log_file() {
    printf '%s/%s.log' "$RUN_DIR" "$1"
}

is_running() {
    local name="$1"
    local binary="$2"
    local file pid process expected_exe
    file="$(pid_file "$name")"
    expected_exe="$(readlink -f "$binary")" || return 1
    if [[ -f "$file" ]] && read -r pid < "$file" &&
        process_matches "$pid" "$binary" "$expected_exe"; then
        RUNNING_PID="$pid"
        return 0
    fi

    for process in /proc/[0-9]*; do
        pid="${process##*/}"
        if process_matches "$pid" "$binary" "$expected_exe"; then
            printf '%s\n' "$pid" > "$file"
            RUNNING_PID="$pid"
            return 0
        fi
    done
    RUNNING_PID=""
    return 1
}

process_matches() {
    local pid="$1"
    local binary="$2"
    local expected_exe="$3"
    local actual_exe command_name
    [[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || return 1
    IFS= read -r -d '' command_name < "/proc/$pid/cmdline" || return 1
    [[ "$command_name" == "$binary" || "$command_name" == "$expected_exe" ]] || return 1
    actual_exe="$(readlink "/proc/$pid/exe")" || return 1
    [[ "$actual_exe" == "$expected_exe" || "$actual_exe" == "$expected_exe (deleted)" ]] || return 1
}

show_config() {
    local public_key="$DATA_DIR/id_ed25519.pub"
    printf '\nRustDesk Server 配置\n'
    printf '服务器地址: %s\n' "$SERVER_ADDR"
    printf '公钥: '
    if [[ -f "$public_key" ]]; then
        cat "$public_key"
        printf '\n'
    else
        printf '未找到 (%s)\n' "$public_key"
    fi
    printf 'ID/Rendezvous: %s\n' "$SERVER_ADDR"
    printf 'Relay: %s:21117\n' "$SERVER_ADDR"
    printf '端口: TCP 21115-21119；UDP 21116\n'
    printf '监听地址: %s\n' "$BIND_ADDRESS"
    printf '数据目录: %s\n' "$DATA_DIR"
    printf '日志目录: %s\n' "$RUN_DIR"
    printf '停止服务: %s stop\n' "$ROOT_DIR/start.sh"
    printf '查看状态: %s status\n\n' "$ROOT_DIR/start.sh"
    if [[ "$SERVER_ADDR" == "127.0.0.1" || "$SERVER_ADDR" == "localhost" ]]; then
        printf '提示: 当前地址仅适用于本机；外网访问请设置 SERVER_ADDR 为公网 IP 或域名，重启服务并配置防火墙/路由端口转发。\n'
    elif [[ "$SERVER_ADDR" =~ ^10\. || "$SERVER_ADDR" =~ ^192\.168\. || "$SERVER_ADDR" =~ ^172\.(1[6-9]|2[0-9]|3[01])\. ]]; then
        printf '提示: 当前地址是局域网地址；外网客户端无法直接访问。需设置 SERVER_ADDR 为公网 IP 或域名、重启服务，并配置防火墙/路由端口转发。\n'
    else
        printf '提示: 远程客户端需能访问该地址；请在防火墙/路由器放行 TCP 21115-21119 和 UDP 21116。\n'
    fi
}

stop_one() {
    local name="$1"
    local binary="$2"
    local file pid expected_exe
    file="$(pid_file "$name")"
    expected_exe="$(readlink -f "$binary")" || return 1
    if ! is_running "$name" "$binary"; then
        rm -f "$file"
        printf '%s 未运行\n' "$name"
        return 0
    fi
    pid="$RUNNING_PID"
    if ! process_matches "$pid" "$binary" "$expected_exe"; then
        rm -f "$file"
        printf '%s 已停止\n' "$name"
        return 0
    fi
    kill "$pid"
    for _ in {1..50}; do
        if ! process_matches "$pid" "$binary" "$expected_exe"; then
            rm -f "$file"
            printf '%s 已停止\n' "$name"
            return 0
        fi
        sleep 0.1
    done
    printf '停止 %s 超时，PID=%s\n' "$name" "$pid" >&2
    return 1
}

start_one() {
    local name="$1"
    local binary="$2"
    shift 2
    local file pid
    file="$(pid_file "$name")"
    if is_running "$name" "$binary"; then
        printf '%s 已在运行 (PID %s)\n' "$name" "$RUNNING_PID"
        return 0
    fi
    rm -f "$file"
    (
        cd "$DATA_DIR"
        exec nohup "$binary" "$@"
    ) >>"$(log_file "$name")" 2>&1 </dev/null &
    pid=$!
    printf '%s\n' "$pid" > "$file"
    sleep 1
    if ! process_matches "$pid" "$binary" "$(readlink -f "$binary")"; then
        rm -f "$file"
        printf '%s 启动失败，日志：%s\n' "$name" "$(log_file "$name")" >&2
        tail -n 30 "$(log_file "$name")" >&2 || true
        return 1
    fi
    printf '%s 已启动 (PID %s)\n' "$name" "$pid"
}

build_binaries() {
    if [[ -x "$HBBS" && -x "$HBBR" ]]; then
        return 0
    fi
    if [[ -x "$HOME/.cargo/bin/cargo" ]]; then
        export PATH="$HOME/.cargo/bin:$PATH"
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        printf '未找到 Cargo。请先安装 Rust，或将 hbbs/hbbr 放入 target/debug/。\n' >&2
        return 1
    fi
    printf '正在编译 hbbs 和 hbbr...\n'
    if rustup toolchain list 2>/dev/null | grep -q '^stable-'; then
        cargo +stable build --bins || {
            printf '编译失败；Linux 请确认已安装构建依赖（例如 pkg-config、libssl-dev）。\n' >&2
            return 1
        }
    else
        cargo build --bins || {
            printf '编译失败；请确认 Rust 工具链版本兼容 Cargo.lock，并安装所需构建依赖。\n' >&2
            return 1
        }
    fi
}

mkdir -p "$RUN_DIR"

case "${1:-start}" in
    start)
        if [[ "$SERVER_ADDR" == *:* && "$SERVER_ADDR" != \[*\] ]]; then
            printf 'IPv6 地址请用方括号格式设置，例如 SERVER_ADDR=[2001:db8::1]。\n' >&2
            exit 1
        fi
        build_binaries
        relay_started=0
        if ! is_running hbbr "$HBBR"; then
            start_one hbbr "$HBBR" --bind "$BIND_ADDRESS" || exit 1
            relay_started=1
        fi
        if ! start_one hbbs "$HBBS" --bind "$BIND_ADDRESS" --relay-servers "$SERVER_ADDR:21117"; then
            if (( relay_started )); then
                stop_one hbbr "$HBBR" || true
            fi
            exit 1
        fi
        show_config
        ;;
    stop)
        stop_one hbbs "$HBBS"
        stop_one hbbr "$HBBR"
        ;;
    status)
        for name in hbbs hbbr; do
            binary="$HBBS"
            [[ "$name" == hbbr ]] && binary="$HBBR"
            if is_running "$name" "$binary"; then
                printf '%s 运行中 (PID %s)\n' "$name" "$RUNNING_PID"
            else
                printf '%s 未运行\n' "$name"
            fi
        done
        show_config
        ;;
    *)
        printf '用法: %s [start|stop|status]\n' "$0" >&2
        exit 2
        ;;
esac
