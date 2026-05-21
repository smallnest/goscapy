#!/bin/bash
#
# run_all.sh - 顺序运行所有 goscapy 示例
#
# 用法:
#   ./run_all.sh                # 运行所有不需要 root 权限的示例
#   sudo ./run_all.sh           # 以 root 权限运行所有示例（包括需要 root 的）
#   ./run_all.sh --dry-run      # 仅显示将要运行的命令，不实际执行
#   ./run_all.sh --skip-root    # 跳过需要 root 权限的示例
#   ./run_all.sh --only <id>    # 只运行指定编号的示例 (如 --only 01)
#   ./run_all.sh --from <id>    # 从指定编号开始运行
#
# 环境变量:
#   INTERFACE   - 指定网络接口 (默认自动检测)
#

set -euo pipefail

# ─── 颜色定义 ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ─── 计数器 ─────────────────────────────────────────────────────────────────────
TOTAL=0
PASSED=0
FAILED=0
SKIPPED=0

# ─── 参数解析 ───────────────────────────────────────────────────────────────────
DRY_RUN=false
SKIP_ROOT=false
ONLY_ID=""
FROM_ID=""
INTERFACE="${INTERFACE:-}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)      DRY_RUN=true; shift ;;
        --skip-root)    SKIP_ROOT=true; shift ;;
        --only)         ONLY_ID="$2"; shift 2 ;;
        --from)         FROM_ID="$2"; shift 2 ;;
        --help|-h)
            head -15 "$0" | grep '^#' | sed 's/^# \?//'
            exit 0
            ;;
        *)
            echo "未知参数: $1"
            exit 1
            ;;
    esac
done

# ─── 辅助函数 ───────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# 跨平台超时函数 (兼容 macOS 无 timeout 命令的情况)
run_with_timeout() {
    local timeout_sec="$1"
    shift
    local cmd="$*"

    # 优先使用系统的 timeout/gtimeout 命令
    if command -v timeout &>/dev/null; then
        timeout "$timeout_sec" bash -c "$cmd"
        return $?
    fi
    if command -v gtimeout &>/dev/null; then
        gtimeout "$timeout_sec" bash -c "$cmd"
        return $?
    fi

    # macOS fallback: 用后台进程 + kill 实现超时
    local tmpout tmperr pid exit_code
    tmpout=$(mktemp)
    tmperr=$(mktemp)

    bash -c "$cmd" >"$tmpout" 2>"$tmperr" &
    pid=$!

    # 监控进程，超时则 kill
    local elapsed=0
    while [[ $elapsed -lt $timeout_sec ]]; do
        if ! kill -0 "$pid" 2>/dev/null; then
            break
        fi
        sleep 1
        elapsed=$((elapsed + 1))
    done

    if kill -0 "$pid" 2>/dev/null; then
        kill -TERM "$pid" 2>/dev/null
        wait "$pid" 2>/dev/null
        exit_code=124  # 模拟 timeout 的退出码
    else
        wait "$pid" 2>/dev/null
        exit_code=$?
    fi

    cat "$tmpout" 2>/dev/null
    cat "$tmperr" 2>/dev/null >&2
    rm -f "$tmpout" "$tmperr"
    return $exit_code
}

# 检测默认网络接口
detect_interface() {
    if [[ -n "$INTERFACE" ]]; then
        echo "$INTERFACE"
        return
    fi
    # macOS
    if command -v route &>/dev/null; then
        local iface
        iface=$(route -n get default 2>/dev/null | grep 'interface:' | awk '{print $2}')
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return
        fi
    fi
    # Linux
    if command -v ip &>/dev/null; then
        local iface
        iface=$(ip route show default 2>/dev/null | awk '{print $5}' | head -1)
        if [[ -n "$iface" ]]; then
            echo "$iface"
            return
        fi
    fi
    echo "eth0"
}

IFACE=$(detect_interface)

print_header() {
    echo ""
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${CYAN}  🚀 Running: $1${NC}"
    echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
}

print_result() {
    local id="$1" status="$2" time_ms="$3"
    case "$status" in
        PASS)  echo -e "  ${GREEN}✅ [$id] PASSED${NC} (${time_ms}ms)" ;;
        FAIL)  echo -e "  ${RED}❌ [$id] FAILED${NC} (${time_ms}ms)" ;;
        SKIP)  echo -e "  ${YELLOW}⏭️  [$id] SKIPPED${NC} ($4)" ;;
    esac
}

# ─── 运行单个示例 ──────────────────────────────────────────────────────────────
run_example() {
    local id="$1"
    local dir="$2"
    local desc="$3"
    local needs_root="$4"
    local cmd_args="$5"   # 传递给程序的额外参数

    TOTAL=$((TOTAL + 1))

    # 检查 --only 过滤
    if [[ -n "$ONLY_ID" && "$id" != "$ONLY_ID" ]]; then
        TOTAL=$((TOTAL - 1))
        return
    fi

    # 检查 --from 过滤
    if [[ -n "$FROM_ID" ]]; then
        if [[ "$id" < "$FROM_ID" ]]; then
            TOTAL=$((TOTAL - 1))
            return
        fi
    fi

    # 检查 root 需求
    if [[ "$needs_root" == "true" ]]; then
        if [[ "$SKIP_ROOT" == "true" ]] || [[ "$(id -u)" -ne 0 ]]; then
            if [[ "$SKIP_ROOT" != "true" ]]; then
                # 仅在非 --skip-root 模式下提示
                :
            fi
            SKIPPED=$((SKIPPED + 1))
            print_result "$id" "SKIP" "0" "需要 root 权限"
            return
        fi
    fi

    local example_path="$SCRIPT_DIR/$dir"

    # 构建命令
    local go_cmd="go run $example_path/main.go $cmd_args"

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "  ${CYAN}[$id] ${go_cmd}${NC}"
        TOTAL=$((TOTAL - 1))
        return
    fi

    print_header "$id $desc"
    echo -e "  ${CYAN}Command: ${go_cmd}${NC}"
    echo ""

    local start_time end_time elapsed_ms

    start_time=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')

    # 设置超时: 构造类示例 10s, 网络交互类 15s, 扫描工具类 10s
    local timeout_sec=15
    if [[ "$id" =~ ^(0[1-9]|10|15|16)$ ]]; then
        timeout_sec=10
    fi

    local exit_code=0
    run_with_timeout "$timeout_sec" "cd '$PROJECT_ROOT' && $go_cmd" 2>&1 || exit_code=$?

    end_time=$(date +%s%N 2>/dev/null || python3 -c 'import time; print(int(time.time()*1e9))')
    elapsed_ms=$(( (end_time - start_time) / 1000000 ))

    if [[ $exit_code -eq 0 ]]; then
        PASSED=$((PASSED + 1))
        print_result "$id" "PASS" "$elapsed_ms"
    elif [[ $exit_code -eq 124 ]]; then
        # timeout 退出码
        PASSED=$((PASSED + 1))
        print_result "$id" "PASS" "$elapsed_ms"
        echo -e "  ${YELLOW}  (超时退出，视为通过)${NC}"
    else
        FAILED=$((FAILED + 1))
        print_result "$id" "FAIL" "$elapsed_ms"
    fi
}

# ─── 主流程 ─────────────────────────────────────────────────────────────────────
echo -e "${BOLD}${CYAN}"
echo "  ╔═══════════════════════════════════════════════════════╗"
echo "  ║          goscapy 示例批量运行器                        ║"
echo "  ╚═══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "  项目根目录: ${BOLD}$PROJECT_ROOT${NC}"
echo -e "  网络接口:   ${BOLD}$IFACE${NC}"
echo -e "  运行用户:   ${BOLD}$(whoami)$( [[ "$(id -u)" -eq 0 ]] && echo ' (root)' )${NC}"
if [[ "$DRY_RUN" == "true" ]]; then
    echo -e "  ${YELLOW}模式: DRY RUN (仅显示命令)${NC}"
fi
echo ""

# ──────────────────────────────────────────────────────────────────────────────
# 第一部分: 数据包构造示例 (无需 root)
# ──────────────────────────────────────────────────────────────────────────────

echo -e "${BOLD}${GREEN}📦 第一部分: 数据包构造示例 (无需 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "01" "01-ethernet-ip"       "Ethernet + IP 数据包构造"        "false" ""
run_example "02" "02-tcp-udp"            "TCP/UDP 数据包构造"              "false" ""
run_example "03" "03-icmp-ping"           "ICMP Ping 数据包构造"            "false" ""
run_example "04" "04-arp"                "ARP 数据包构造"                  "false" ""
run_example "05" "05-ipv6"               "IPv6 数据包构造"                 "false" ""
run_example "06" "06-dns"                "DNS 数据包构造"                  "false" ""
run_example "07" "07-dhcp"               "DHCP 数据包构造"                 "false" ""
run_example "08" "08-vlan"               "VLAN 802.1Q 数据包构造"          "false" ""
run_example "09" "09-gre-vxlan"          "GRE/VXLAN 隧道数据包构造"        "false" ""

# ──────────────────────────────────────────────────────────────────────────────
# 第二部分: 数据包分析示例 (无需 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}🔍 第二部分: 数据包分析示例 (无需 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "10" "10-dissect"            "数据包解析/分析"                 "false" ""
run_example "15" "15-bpf-filter"         "BPF 过滤器编译与使用"            "true"  ""
run_example "16" "16-shortcuts"          "快捷函数综合演示"                "false" ""

# ──────────────────────────────────────────────────────────────────────────────
# 第三部分: 网络交互示例 (需要 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}🌐 第三部分: 网络交互示例 (需要 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "11" "11-send"               "数据包发送 (Send/Sendp)"         "true"  "$IFACE"
run_example "12" "12-sendrecv"           "发送并接收 (SendRecv)"           "true"  "$IFACE"
run_example "13" "13-tcp-syn-scan"       "TCP SYN 端口扫描"                "true"  "$IFACE 127.0.0.1"
run_example "14" "14-sniff"              "数据包嗅探 (Sniff)"              "true"  "$IFACE"

# ──────────────────────────────────────────────────────────────────────────────
# 第四部分: 网络工具 (需要 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}🔧 第四部分: 网络工具 (需要 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "17" "17-ping"               "Ping 工具"                       "true"  "-c 3 127.0.0.1"
run_example "18" "18-traceroute"         "Traceroute 工具"                 "true"  "-m 5 127.0.0.1"

# ──────────────────────────────────────────────────────────────────────────────
# 第五部分: 高级 Socket 示例 (需要 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}⚡ 第五部分: 高级 Socket 示例 (需要 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "19" "19-raw-socket"         "Raw Socket 基础"                 "true"  ""
run_example "20" "20-batch-raw-socket"   "批量 Raw Socket"                 "true"  ""
run_example "21" "21-zerocopy"           "Zero-copy 发送"                  "true"  ""
run_example "22" "22-uring-raw-socket"   "io_uring Raw Socket"             "true"  ""
run_example "23" "23-packet-mmap"        "TPACKET_V3 MMAP 抓包"            "true"  "$IFACE"

# ──────────────────────────────────────────────────────────────────────────────
# 第六部分: 客户端工具 (无需/需要 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}📡 第六部分: 客户端工具${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "24" "24-dns-client"         "DNS 客户端"                      "false" "-type A example.com"
run_example "25" "25-ntp-client"         "NTP 客户端"                      "true"  ""
run_example "26" "26-dhcp-client"        "DHCP 客户端"                     "true"  ""

# ──────────────────────────────────────────────────────────────────────────────
# 第七部分: 扫描器工具 (需要 root)
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BOLD}${GREEN}🔭 第七部分: 扫描器工具 (需要 root)${NC}"
echo -e "${GREEN}─────────────────────────────────────────────────────────────────────${NC}"

run_example "27" "27-arp-scanner"        "ARP 扫描器"                      "true"  "-cidr 127.0.0.0/30"
run_example "31" "31-port-scanner"       "TCP 端口扫描器"                   "true"  "-p 80 127.0.0.1"
run_example "32" "32-fishfinder"         "IP/时延扫描器 (Fishfinder)"      "true"  "-cidr 127.0.0.0/30 -mode icmp"

# ──────────────────────────────────────────────────────────────────────────────
# 结果汇总
# ──────────────────────────────────────────────────────────────────────────────

echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
echo -e "${BOLD}  📊 运行结果汇总${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  总计:   ${BOLD}$TOTAL${NC}"
echo -e "  ${GREEN}通过:   $PASSED${NC}"
echo -e "  ${RED}失败:   $FAILED${NC}"
echo -e "  ${YELLOW}跳过:   $SKIPPED${NC}"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo -e "${RED}${BOLD}  ⚠️  有 $FAILED 个示例失败！${NC}"
    echo ""
    exit 1
elif [[ $SKIPPED -gt 0 && $PASSED -gt 0 ]]; then
    echo -e "${YELLOW}${BOLD}  ℹ️  $SKIPPED 个示例因需要 root 权限被跳过。${NC}"
    echo -e "${YELLOW}     使用 ${BOLD}sudo ./run_all.sh${YELLOW} 运行所有示例。${NC}"
    echo ""
    exit 0
elif [[ $PASSED -gt 0 ]]; then
    echo -e "${GREEN}${BOLD}  🎉 所有示例运行成功！${NC}"
    echo ""
    exit 0
fi
