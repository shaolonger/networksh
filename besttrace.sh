#!/usr/bin/env bash
# =========================================================
# BestTrace Safe Single File
# - 保留原 besttrace.sh 菜单、测试节点与线路分析逻辑
# - 移除 管道执行远程 sh 远程脚本执行
# - 内置 NextTrace 二进制下载逻辑，仅下载二进制，不执行远程 sh
# - 使用 mktemp 临时文件、输入校验、HTTPS URL 校验、可选 SHA256 校验
# - 自动处理 NextTrace 权限：root/capabilities 用 ICMP，普通用户自动降级 TCP
#
# 安全模式建议：
#   1) 已安装 nexttrace：直接运行本脚本，不会下载任何内容。
#   2) 首次安装但要求校验：
#        NEXTTRACE_SHA256=<nexttrace二进制sha256> bash besttrace_safe_single.sh
#   3) 完全禁止自动下载：
#        BESTTRACE_NO_INSTALL=1 bash besttrace_safe_single.sh
#
# 注意：本脚本消除了“远程脚本注入”风险，但如果允许自动下载 nexttrace 二进制，
#       仍然存在二进制供应链风险。要进一步降低风险，请使用 NEXTTRACE_SHA256。
# =========================================================

set -Eeuo pipefail

# ---------- 颜色 ----------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
SKYBLUE='\033[0;36m'
PLAIN='\033[0m'
BOLD='\033[1m'
PURPLE='\033[0;35m'

# ---------- 全局配置 ----------
SYSTEM_BIN_DIR="${NT_INSTALL_SYSTEM_BIN_DIR:-/usr/local/bin}"
USER_BIN_DIR="${NT_INSTALL_USER_BIN_DIR:-${HOME:-}/.local/bin}"
BIN_NAME="nexttrace"
GITHUB_RELEASE_BASE="https://github.com/nxtrace/NTrace-core/releases/latest/download"
NXTRACE_API_HOST="www.nxtrace.org"
NXTRACE_API_PATH="/api/dist/core"

# 默认不使用 API 镜像列表，避免动态 URL 扩大供应链面。
# 如 GitHub 下载困难，可显式启用：NXTRACE_USE_API_MIRRORS=1 bash besttrace_safe_single.sh
NXTRACE_USE_API_MIRRORS="${NXTRACE_USE_API_MIRRORS:-0}"

# 可选：指定目标架构，例如 amd64/arm64/386/armv7 等。
ARCH_OVERRIDE="${NXTRACE_ARCH:-}"

# 可选：下载后强制校验 SHA256。
NEXTTRACE_SHA256="${NEXTTRACE_SHA256:-}"

# 可选：禁止自动安装/下载。缺少 nexttrace 时直接退出。
BESTTRACE_NO_INSTALL="${BESTTRACE_NO_INSTALL:-0}"

# 路由测试协议模式：auto|icmp|tcp|udp。
# auto：有 root/capabilities 时用 ICMP；否则自动退回 TCP:443，避免普通用户权限失败。
BESTTRACE_TRACE_MODE="${BESTTRACE_TRACE_MODE:-auto}"
BESTTRACE_TCP_PORT="${BESTTRACE_TCP_PORT:-443}"
BESTTRACE_UDP_PORT="${BESTTRACE_UDP_PORT:-33494}"

# 可选：用户指定现有 nexttrace 路径。
NEXTTRACE_CMD="${NEXTTRACE_BIN:-}"

TEMP_FILES=()
ROWS_CT=()
ROWS_CU=()
ROWS_CM=()
ROWS_EDU=()
ROWS_OTHER=()
TRACE_ARGS=()
TRACE_MODE_EFFECTIVE=""

# ---------- 基础工具 ----------
info() { printf '%b\n' "${GREEN}==>${PLAIN} $*"; }
warn() { printf '%b\n' "${YELLOW}warning:${PLAIN} $*" >&2; }
die()  { printf '%b\n' "${RED}error:${PLAIN} $*" >&2; exit 1; }

cleanup() {
    local f
    for f in "${TEMP_FILES[@]:-}"; do
        [ -n "${f:-}" ] && [ -e "$f" ] && rm -f -- "$f" >/dev/null 2>&1 || true
    done
}
trap cleanup EXIT INT TERM

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

make_temp_file() {
    local dir="${1:-${TMPDIR:-/tmp}}"
    local prefix="${2:-besttrace}"
    local f
    f="$(mktemp "${dir%/}/${prefix}.XXXXXX")" || die "无法创建临时文件：${dir}"
    TEMP_FILES+=("$f")
    printf '%s\n' "$f"
}

sha256_file() {
    local file="$1"
    if command_exists sha256sum; then
        sha256sum "$file" | awk '{print $1}'
    elif command_exists shasum; then
        shasum -a 256 "$file" | awk '{print $1}'
    else
        return 1
    fi
}

download_url_to_file() {
    local url="$1"
    local output="$2"

    case "$url" in
        https://*) ;;
        *) warn "跳过非 HTTPS 下载地址：$url"; return 1 ;;
    esac

    if command_exists curl; then
        curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 180 \
             --retry 3 --retry-delay 1 -o "$output" "$url"
    elif command_exists wget; then
        wget -q --https-only --timeout=10 --tries=3 --waitretry=1 -O "$output" "$url"
    else
        die "需要 curl 或 wget 才能下载 nexttrace 二进制。"
    fi
}

fetch_text_https() {
    local url="$1"

    case "$url" in
        https://*) ;;
        *) return 1 ;;
    esac

    if command_exists curl; then
        curl -fsSL --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time 30 "$url"
    elif command_exists wget; then
        wget -q --https-only --timeout=10 -O - "$url"
    else
        return 1
    fi
}

normalize_arch() {
    case "$1" in
        amd64|x86_64) printf '%s\n' "amd64" ;;
        386|i386|i486|i586|i686) printf '%s\n' "386" ;;
        arm64|aarch64) printf '%s\n' "arm64" ;;
        armv5|armv5l|armv5tel) printf '%s\n' "armv5" ;;
        armv6|armv6l) printf '%s\n' "armv6" ;;
        armv7|armv7l|armv7ml|armv8l) printf '%s\n' "armv7" ;;
        mips) printf '%s\n' "mips" ;;
        mipsel|mipsle) printf '%s\n' "mipsle" ;;
        mips64) printf '%s\n' "mips64" ;;
        mips64el|mips64le) printf '%s\n' "mips64le" ;;
        loongarch64|loong64) printf '%s\n' "loong64" ;;
        ppc64) printf '%s\n' "ppc64" ;;
        ppc64le) printf '%s\n' "ppc64le" ;;
        riscv64) printf '%s\n' "riscv64" ;;
        s390x) printf '%s\n' "s390x" ;;
        *) return 1 ;;
    esac
}

detect_os() {
    case "$(uname -s 2>/dev/null || printf 'unknown')" in
        Linux) printf '%s\n' "linux" ;;
        Darwin) printf '%s\n' "darwin" ;;
        FreeBSD) printf '%s\n' "freebsd" ;;
        OpenBSD) printf '%s\n' "openbsd" ;;
        DragonFly) printf '%s\n' "dragonfly" ;;
        *) return 1 ;;
    esac
}

detect_arch() {
    if [ -n "$ARCH_OVERRIDE" ]; then
        normalize_arch "$ARCH_OVERRIDE" || die "不支持的架构覆盖值：$ARCH_OVERRIDE"
        return 0
    fi
    normalize_arch "$(uname -m 2>/dev/null || printf 'unknown')" \
        || die "不支持的系统架构：$(uname -m 2>/dev/null || printf 'unknown')"
}

asset_name_for_current_system() {
    local os arch
    os="$(detect_os)" || die "不支持的操作系统：$(uname -s 2>/dev/null || printf 'unknown')"
    arch="$(detect_arch)"

    if [ "$os" = "darwin" ]; then
        printf '%s\n' "${BIN_NAME}_darwin_universal"
    else
        printf '%s\n' "${BIN_NAME}_${os}_${arch}"
    fi
}

can_use_dir() {
    local dir="$1"
    [ -d "$dir" ] || mkdir -p "$dir" >/dev/null 2>&1 || return 1
    [ -w "$dir" ]
}

resolve_install_path() {
    if [ -n "${BESTTRACE_BIN_DIR:-}" ]; then
        can_use_dir "$BESTTRACE_BIN_DIR" || die "指定目录不可写：$BESTTRACE_BIN_DIR"
        printf '%s/%s\n' "${BESTTRACE_BIN_DIR%/}" "$BIN_NAME"
        return 0
    fi

    if can_use_dir "$SYSTEM_BIN_DIR"; then
        printf '%s/%s\n' "${SYSTEM_BIN_DIR%/}" "$BIN_NAME"
        return 0
    fi

    [ -n "${HOME:-}" ] || die "HOME 未设置，且无法写入 $SYSTEM_BIN_DIR。请预先安装 nexttrace 或设置 BESTTRACE_BIN_DIR。"
    can_use_dir "$USER_BIN_DIR" || die "用户安装目录不可写：$USER_BIN_DIR"
    printf '%s/%s\n' "${USER_BIN_DIR%/}" "$BIN_NAME"
}

candidate_urls_for_asset() {
    local asset="$1"
    local response old_ifs candidate

    if [ "$NXTRACE_USE_API_MIRRORS" = "1" ]; then
        response="$(fetch_text_https "https://${NXTRACE_API_HOST}${NXTRACE_API_PATH}/${asset}" 2>/dev/null || true)"
        if [ -n "$response" ]; then
            old_ifs="$IFS"
            IFS='|'
            # shellcheck disable=SC2086
            set -- $response
            IFS="$old_ifs"
            for candidate in "$@"; do
                case "$candidate" in
                    https://*) printf '%s\n' "$candidate" ;;
                    *) warn "镜像列表中存在非 HTTPS 地址，已跳过：$candidate" ;;
                esac
            done
        else
            warn "无法获取 NextTrace 镜像列表，将使用 GitHub release。"
        fi
    fi

    printf '%s\n' "${GITHUB_RELEASE_BASE}/${asset}"
}

verify_downloaded_binary() {
    local file="$1"

    [ -s "$file" ] || return 1

    if [ -n "$NEXTTRACE_SHA256" ]; then
        local got expected_lower got_lower
        got="$(sha256_file "$file")" || die "系统缺少 sha256sum/shasum，无法执行 NEXTTRACE_SHA256 校验。"
        expected_lower="$(printf '%s' "$NEXTTRACE_SHA256" | tr '[:upper:]' '[:lower:]')"
        got_lower="$(printf '%s' "$got" | tr '[:upper:]' '[:lower:]')"
        if [ "$got_lower" != "$expected_lower" ]; then
            warn "SHA256 校验失败。"
            warn "期望：$NEXTTRACE_SHA256"
            warn "实际：$got"
            return 1
        fi
    else
        warn "未设置 NEXTTRACE_SHA256，无法对下载的 nexttrace 二进制做强完整性校验。"
    fi

    chmod 0755 "$file" >/dev/null 2>&1 || return 1
    "$file" --version >/dev/null 2>&1 || return 1
}

install_nexttrace_binary() {
    [ "$BESTTRACE_NO_INSTALL" = "1" ] && die "未找到 nexttrace，且 BESTTRACE_NO_INSTALL=1 禁止自动安装。"

    local asset install_path install_dir tmp candidate installed_from
    asset="$(asset_name_for_current_system)"
    install_path="$(resolve_install_path)"
    install_dir="$(dirname "$install_path")"

    info "未发现 nexttrace，准备下载二进制：$asset"
    info "安装路径：$install_path"

    tmp="$(make_temp_file "$install_dir" ".${BIN_NAME}.download")"

    installed_from=""
    while IFS= read -r candidate; do
        [ -n "$candidate" ] || continue
        info "尝试下载：$candidate"
        if download_url_to_file "$candidate" "$tmp" >/dev/null 2>&1; then
            if verify_downloaded_binary "$tmp"; then
                installed_from="$candidate"
                break
            fi
        fi
        rm -f -- "$tmp" >/dev/null 2>&1 || true
        tmp="$(make_temp_file "$install_dir" ".${BIN_NAME}.download")"
    done < <(candidate_urls_for_asset "$asset")

    [ -n "$installed_from" ] || die "未能下载并验证可运行的 nexttrace。建议手动安装后重试。"

    mv -f -- "$tmp" "$install_path" || die "无法写入安装路径：$install_path"
    chmod 0755 "$install_path" >/dev/null 2>&1 || true
    NEXTTRACE_CMD="$install_path"

    info "nexttrace 已安装：$NEXTTRACE_CMD"
    info "下载来源：$installed_from"
}

ensure_nexttrace() {
    if [ -n "$NEXTTRACE_CMD" ]; then
        [ -x "$NEXTTRACE_CMD" ] || die "NEXTTRACE_BIN 指定的文件不可执行：$NEXTTRACE_CMD"
        "$NEXTTRACE_CMD" --version >/dev/null 2>&1 || die "NEXTTRACE_BIN 指定的程序无法通过 --version 检查：$NEXTTRACE_CMD"
        return 0
    fi

    if command_exists nexttrace; then
        NEXTTRACE_CMD="$(command -v nexttrace)"
        return 0
    fi

    if [ -x "/usr/local/bin/nexttrace" ]; then
        NEXTTRACE_CMD="/usr/local/bin/nexttrace"
        return 0
    fi

    install_nexttrace_binary
}

# ---------- 输出与分析 ----------
next_sep() {
    echo -e "${SKYBLUE}----------------------------------------------------------------------${PLAIN}"
}

strip_ansi() {
    sed 's/\x1b\[[0-9;]*m//g'
}

analyze_route() {
    local log_content=$1
    local isp_type=$2
    local target_name=$3
    local target_ip=$4

    local clean_content
    clean_content="$(printf '%s\n' "$log_content" | strip_ansi)"

    local has_as4809 has_as9929 has_as4837 has_cmin2 has_cmi domestic_segment domestic_has_4809
    has_as4809="$(printf '%s\n' "$clean_content" | grep -E "AS4809|59\.43\." || true)"
    has_as9929="$(printf '%s\n' "$clean_content" | grep -E "AS9929|99\.29\.|AS10099" || true)"
    has_as4837="$(printf '%s\n' "$clean_content" | grep -E "AS4837|219\.158\." || true)"
    has_cmin2="$(printf '%s\n' "$clean_content" | grep -E "AS58807" || true)"
    has_cmi="$(printf '%s\n' "$clean_content" | grep -E "AS58453|AS9808|223\.120\." || true)"
    domestic_segment="$(printf '%s\n' "$clean_content" | grep -iE "China|CN|Beijing|Shanghai|Guangzhou|Shenzhen|Chengdu|Anhui|Sichuan|Guangdong" || true)"
    domestic_has_4809="$(printf '%s\n' "$domestic_segment" | grep -E "AS4809|59\.43\." || true)"

    local ret_color_type=""

    echo -e "${YELLOW}>>> [智能分析] 线路判定 (目标: $isp_type)：${PLAIN}"

    if [ -n "$domestic_has_4809" ]; then
        echo -e "   类型：${GREEN}${BOLD}电信 CN2 GIA (AS4809)${PLAIN}"
        echo -e "   详情：检测到回程国内段走 AS4809，顶级线路。"
        ret_color_type="${GREEN}CN2 GIA${PLAIN}"
    elif [ -n "$has_as9929" ]; then
        echo -e "   类型：${GREEN}${BOLD}联通 9929 (CU Premium)${PLAIN}"
        echo -e "   详情：检测到 AS9929/AS10099 联通精品骨干。"
        ret_color_type="${GREEN}联通 9929${PLAIN}"
    elif [ -n "$has_cmin2" ]; then
        echo -e "   类型：${GREEN}${BOLD}移动 CMIN2 (AS58807)${PLAIN}"
        echo -e "   详情：检测到移动高端精品网 AS58807。"
        ret_color_type="${GREEN}移动 CMIN2${PLAIN}"
    elif [ -n "$has_as4809" ]; then
        echo -e "   类型：${YELLOW}${BOLD}电信 CN2 GT (Global Transit)${PLAIN}"
        echo -e "   详情：检测到 AS4809，但未确认国内段全程 CN2 GIA。"
        ret_color_type="${YELLOW}CN2 GT${PLAIN}"
    elif [ -n "$has_as4837" ]; then
        echo -e "   类型：${SKYBLUE}联通 4837 (169 Backbone)${PLAIN}"
        echo -e "   详情：联通民用骨干网。"
        ret_color_type="${SKYBLUE}联通 4837${PLAIN}"
    elif [ -n "$has_cmi" ]; then
        echo -e "   类型：${SKYBLUE}移动 CMI (AS58453/9808)${PLAIN}"
        echo -e "   详情：走移动国际线路 CMI。"
        ret_color_type="${SKYBLUE}移动 CMI${PLAIN}"
    else
        case "$isp_type" in
            "CT")
                echo -e "   类型：${RED}电信 163 骨干网 (AS4134)${PLAIN}"
                ret_color_type="${RED}163 骨干${PLAIN}"
                ;;
            "CU")
                echo -e "   类型：${RED}联通普通线路${PLAIN}"
                ret_color_type="联通普通"
                ;;
            "CM")
                echo -e "   类型：${PURPLE}移动普通线路${PLAIN}"
                ret_color_type="${PURPLE}移动普通${PLAIN}"
                ;;
            "EDU")
                echo -e "   类型：${SKYBLUE}教育网 (CERNET)${PLAIN}"
                ret_color_type="${SKYBLUE}教育网${PLAIN}"
                ;;
            *)
                echo -e "   类型：其他/混合网络"
                ret_color_type="其他网络"
                ;;
        esac
    fi

    local name_len pad_spaces summary_line
    name_len=${#target_name}
    pad_spaces=""
    if [[ $name_len -eq 4 ]]; then pad_spaces="        "; fi
    if [[ $name_len -eq 5 ]]; then pad_spaces="      "; fi
    if [[ $name_len -eq 3 ]]; then pad_spaces="          "; fi
    if [[ $name_len -eq 6 ]]; then pad_spaces="    "; fi
    if [[ -z "$pad_spaces" ]]; then pad_spaces="    "; fi

    summary_line="$(printf "%s%s %-18s %-20b" "$target_name" "$pad_spaces" "$target_ip" "$ret_color_type")"

    case "$isp_type" in
        CT) ROWS_CT+=("$summary_line") ;;
        CU) ROWS_CU+=("$summary_line") ;;
        CM) ROWS_CM+=("$summary_line") ;;
        EDU) ROWS_EDU+=("$summary_line") ;;
        *) ROWS_OTHER+=("$summary_line") ;;
    esac
}

detect_isp_type() {
    local log_content=$1
    local lower_content
    lower_content="$(printf '%s\n' "$log_content" | tr '[:upper:]' '[:lower:]')"

    if printf '%s\n' "$lower_content" | grep -qE "telecom|dx|as4134|as4809"; then
        echo "CT"
    elif printf '%s\n' "$lower_content" | grep -qE "unicom|lt|as4837|as9929|as10099"; then
        echo "CU"
    elif printf '%s\n' "$lower_content" | grep -qE "mobile|yd|as9808|as58453|as58807|cmi"; then
        echo "CM"
    elif printf '%s\n' "$lower_content" | grep -qE "education|cernet|edu"; then
        echo "EDU"
    else
        echo "OTHER"
    fi
}

print_banner() {
    clear || true
    echo -e "${GREEN}#############################################################${PLAIN}"
    echo -e "${GREEN}#       BestTrace Safe - Linux VPS 回程路由一键测试         #${PLAIN}"
    echo -e "${GREEN}#       单文件版：无 管道执行远程 sh 远程脚本执行          #${PLAIN}"
    echo -e "${GREEN}#       建议：预装 nexttrace 或设置 NEXTTRACE_SHA256        #${PLAIN}"
    echo -e "${GREEN}#############################################################${PLAIN}"
}

print_final_summary() {
    echo ""
    echo -e "${GREEN}#############################################################${PLAIN}"
    echo -e "${GREEN}#       BestTrace Safe - Linux VPS 回程路由测试汇总         #${PLAIN}"
    echo -e "${GREEN}#       单文件版：无 管道执行远程 sh 远程脚本执行          #${PLAIN}"
    echo -e "${GREEN}#############################################################${PLAIN}"

    echo -e "节点名称         IP 地址            线路类型"
    echo "-------------------------------------------------------------"

    local line
    for line in "${ROWS_CT[@]:-}"; do echo -e "$line"; done
    for line in "${ROWS_CU[@]:-}"; do echo -e "$line"; done
    for line in "${ROWS_CM[@]:-}"; do echo -e "$line"; done
    for line in "${ROWS_EDU[@]:-}"; do echo -e "$line"; done
    for line in "${ROWS_OTHER[@]:-}"; do echo -e "$line"; done

    echo "-------------------------------------------------------------"
    echo -e "${YELLOW}* 图例: ${GREEN}绿色=高端(GIA/9929/CMIN2)${PLAIN} | ${SKYBLUE}蓝色=主流(4837/CMI)${PLAIN} | ${RED}红色=普通${PLAIN}"
    echo -e "${YELLOW}* 提示: 线路类型判断结果仅供参考，具体以实际路由和表现为准${PLAIN}"
    echo ""
}

is_valid_ipv4() {
    local ip="$1" IFS=.
    local -a parts
    read -r -a parts <<< "$ip"
    [ "${#parts[@]}" -eq 4 ] || return 1

    local part
    for part in "${parts[@]}"; do
        [[ "$part" =~ ^[0-9]+$ ]] || return 1
        [ "$part" -ge 0 ] 2>/dev/null && [ "$part" -le 255 ] 2>/dev/null || return 1
    done
}

is_valid_target() {
    local target="$1"

    [ -n "$target" ] || return 1
    [[ "$target" != -* ]] || return 1
    [[ "$target" != *[[:space:]\;\&\|\`\$\(\)\<\>\{\}\[\]\'\"]* ]] || return 1

    if [[ "$target" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
        is_valid_ipv4 "$target"
        return $?
    fi

    # 宽松 IPv6 校验：只允许十六进制、冒号和点，并且必须包含冒号。
    if [[ "$target" == *:* ]] && [[ "$target" =~ ^[0-9A-Fa-f:\.]+$ ]]; then
        return 0
    fi

    # 域名校验：至少包含一个点，单段不超过 63 字符。
    if [[ "$target" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.?$ ]]; then
        return 0
    fi

    return 1
}


can_use_icmp_mode() {
    # root 运行时可以直接使用 ICMP。
    if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
        return 0
    fi

    # 普通用户需要二进制具备 Linux capabilities。
    if command_exists getcap && [[ -n "${NEXTTRACE_CMD:-}" ]] && [[ -e "$NEXTTRACE_CMD" ]]; then
        local caps
        caps="$(getcap "$NEXTTRACE_CMD" 2>/dev/null || true)"
        [[ "$caps" == *cap_net_raw* && "$caps" == *cap_net_admin* ]] && return 0
    fi

    return 1
}

try_setcap_nexttrace() {
    # root 下尽量给 nexttrace 设置 capabilities，方便之后普通用户运行。
    # 失败不退出：某些 VPS/容器文件系统不支持 capabilities，root 当前运行仍然可用。
    [[ "$(uname -s 2>/dev/null || true)" == "Linux" ]] || return 0
    [[ ${EUID:-$(id -u)} -eq 0 ]] || return 0
    command_exists setcap || return 0
    [[ -n "${NEXTTRACE_CMD:-}" && -f "$NEXTTRACE_CMD" ]] || return 0

    if setcap cap_net_raw,cap_net_admin+eip "$NEXTTRACE_CMD" >/dev/null 2>&1; then
        info "已为 nexttrace 设置 capabilities：cap_net_raw,cap_net_admin+eip"
    else
        warn "无法为 nexttrace 设置 capabilities；如果当前是 root 运行，测试仍可继续。"
    fi
}

resolve_trace_mode() {
    case "$BESTTRACE_TRACE_MODE" in
        auto|AUTO)
            if can_use_icmp_mode; then
                TRACE_MODE_EFFECTIVE="ICMP"
                TRACE_ARGS=()
            else
                TRACE_MODE_EFFECTIVE="TCP:${BESTTRACE_TCP_PORT}"
                TRACE_ARGS=(--tcp --port "$BESTTRACE_TCP_PORT")
                warn "当前不是 root，且 nexttrace 未获得 raw socket capabilities；已自动改用 TCP:${BESTTRACE_TCP_PORT} 模式。"
                warn "如需 ICMP 模式，请用 sudo/root 运行，或执行：sudo setcap cap_net_raw,cap_net_admin+eip \"$NEXTTRACE_CMD\""
            fi
            ;;
        icmp|ICMP)
            if ! can_use_icmp_mode; then
                die "ICMP 模式需要 root 或 capabilities。请用 sudo/root 运行，或执行：sudo setcap cap_net_raw,cap_net_admin+eip \"$NEXTTRACE_CMD\""
            fi
            TRACE_MODE_EFFECTIVE="ICMP"
            TRACE_ARGS=()
            ;;
        tcp|TCP)
            TRACE_MODE_EFFECTIVE="TCP:${BESTTRACE_TCP_PORT}"
            TRACE_ARGS=(--tcp --port "$BESTTRACE_TCP_PORT")
            ;;
        udp|UDP)
            TRACE_MODE_EFFECTIVE="UDP:${BESTTRACE_UDP_PORT}"
            TRACE_ARGS=(--udp --port "$BESTTRACE_UDP_PORT")
            ;;
        *)
            die "无效 BESTTRACE_TRACE_MODE：$BESTTRACE_TRACE_MODE，可选 auto|icmp|tcp|udp"
            ;;
    esac
}

run_trace_and_analyze() {
    local target_ip="$1"
    local target_name="$2"
    local isp_type="$3"
    local log_file raw_log

    log_file="$(make_temp_file "${TMPDIR:-/tmp}" "besttrace.log")"

    echo -e "正在测试: ${GREEN}${target_name}${PLAIN} [${target_ip}]"

    if "$NEXTTRACE_CMD" -q 1 -M "${TRACE_ARGS[@]}" "$target_ip" | tee "$log_file"; then
        raw_log="$(cat "$log_file")"
        analyze_route "$raw_log" "$isp_type" "$target_name" "$target_ip"
    else
        warn "nexttrace 测试失败：$target_name [$target_ip]"
    fi
}

# ---------- 数据源 ----------
ip_list=(
    "219.141.147.210" "202.106.50.1" "221.179.155.161"
    "202.96.209.133" "210.22.97.1" "211.136.112.200"
    "202.96.128.86" "210.21.196.6" "120.196.165.24"
    "118.112.11.12" "119.6.6.6" "211.137.96.205"
    "202.112.14.151"
)

ip_addr=(
    "北京电信" "北京联通" "北京移动"
    "上海电信" "上海联通" "上海移动"
    "广州电信" "广州联通" "广州移动"
    "成都电信" "成都联通" "成都移动"
    "成都教育网"
)

isp_codes=(
    "CT" "CU" "CM"
    "CT" "CU" "CM"
    "CT" "CU" "CM"
    "CT" "CU" "CM"
    "EDU"
)

main() {
    ensure_nexttrace
    try_setcap_nexttrace
    resolve_trace_mode
    print_banner

    echo -e "nexttrace 路径：${SKYBLUE}${NEXTTRACE_CMD}${PLAIN}"
    echo -e "测试协议模式：${SKYBLUE}${TRACE_MODE_EFFECTIVE}${PLAIN}"
    echo ""
    echo -e "请选择测试模式："
    echo -e "${GREEN}0.${PLAIN} 测试所有节点 (默认 - 直接回车)"
    echo -e "${SKYBLUE}1.${PLAIN} 仅测试 电信 (China Telecom)"
    echo -e "${SKYBLUE}2.${PLAIN} 仅测试 联通 (China Unicom)"
    echo -e "${SKYBLUE}3.${PLAIN} 仅测试 移动 (China Mobile)"
    echo -e "${SKYBLUE}4.${PLAIN} 仅测试 教育网 (Education)"
    echo -e "${YELLOW}5.${PLAIN} 自定义 IP/域名 测试 (自动识别运营商)"
    echo ""

    local choice mode_name custom_target raw_log detected_isp
    read -r -p "请输入选项 [0-5]: " choice < /dev/tty || choice=""
    if [[ -z "$choice" ]]; then choice="0"; fi

    case "$choice" in
        0) mode_name="测试所有节点" ;;
        1) mode_name="仅测试 电信 (China Telecom)" ;;
        2) mode_name="仅测试 联通 (China Unicom)" ;;
        3) mode_name="仅测试 移动 (China Mobile)" ;;
        4) mode_name="仅测试 教育网 (Education)" ;;
        5) mode_name="自定义 IP/域名 测试" ;;
        *) die "无效选项：$choice" ;;
    esac

    if [[ "$choice" == "5" ]]; then
        echo ""
        read -r -p "请输入目标 IP 或域名: " custom_target < /dev/tty || die "无法读取输入。"
        is_valid_target "$custom_target" || die "目标格式不安全或不合法：$custom_target"

        echo -e "\n正在测试: ${GREEN}自定义测速点${PLAIN} [${custom_target}]"
        local log_file
        log_file="$(make_temp_file "${TMPDIR:-/tmp}" "besttrace.custom.log")"

        if "$NEXTTRACE_CMD" -q 1 -M "${TRACE_ARGS[@]}" "$custom_target" | tee "$log_file"; then
            raw_log="$(cat "$log_file")"
            detected_isp="$(detect_isp_type "$raw_log")"
            analyze_route "$raw_log" "$detected_isp" "自定义测速点" "$custom_target"
            print_final_summary
        else
            die "nexttrace 自定义测试失败。"
        fi
        exit 0
    fi

    clear || true
    echo -e "${GREEN}=== 开始测试 (模式: $mode_name / 协议: $TRACE_MODE_EFFECTIVE) ===${PLAIN}"
    next_sep

    local len count i target_ip target_name isp_type should_run
    len=${#ip_list[@]}
    count=0

    for ((i=0; i<len; i++)); do
        target_ip="${ip_list[$i]}"
        target_name="${ip_addr[$i]}"
        isp_type="${isp_codes[$i]}"

        should_run=false
        case "$choice" in
            0) should_run=true ;;
            1) [[ "$isp_type" == "CT" ]] && should_run=true ;;
            2) [[ "$isp_type" == "CU" ]] && should_run=true ;;
            3) [[ "$isp_type" == "CM" ]] && should_run=true ;;
            4) [[ "$isp_type" == "EDU" ]] && should_run=true ;;
        esac

        if $should_run; then
            ((++count))
            run_trace_and_analyze "$target_ip" "$target_name" "$isp_type"
            next_sep
            sleep 1
        fi
    done

    if [[ $count -eq 0 ]]; then
        echo -e "${YELLOW}提示：该模式下没有匹配的测试节点。${PLAIN}"
    else
        print_final_summary
    fi
}

main "$@"
