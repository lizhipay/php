#!/usr/bin/env bash
#
# BaoTa / aaPanel PHP security updater
#
# Rebuilds every PHP version installed under /www/server/php so that it is no
# longer affected by CVE-2026-109618 / CVE-2026-109619 (unauthenticated RCE):
#   8.2 and newer  -> latest release of the same branch from php.net
#   7.4 / 8.0 / 8.1 -> last release + official backport patch (embedded below)
#   5.x - 7.3      -> no fix exists; sets session.upload_progress.enabled = Off
#
# Advisory: https://www.php.net/archive/2026.php#2026-10-21-5
#
# Usage: bash bt-php-security-update.sh [--check] [--only 74,82] [--jobs N] [-y]
# Env:   PHP_MIRROR  extra base URL serving php-X.Y.Z.tar.gz (always SHA256-verified)

PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
LC_ALL=C
export PATH LC_ALL
set -o pipefail

readonly SCRIPT_VERSION="1.0.0"
readonly ADVISORY_URL="https://www.php.net/archive/2026.php#2026-10-21-5"
readonly CVE_LABEL="CVE-2026-109618 / CVE-2026-109619"
readonly PATCH_MARKER=".security-patch-cve-2026-109618"
readonly MIN_FREE_MB=2048

declare -A FIXED_RELEASE=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)
declare -A KNOWN_SHA256=(
	[8.5.12]=81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525
	[8.4.27]=5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f
	[8.3.36]=c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53
	[8.2.35]=9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910
	[8.1.34]=3c5b060ec8e0d5dd1d8237823f3161cc8bc5342aab3c46893eba9857759c4bfa
	[8.0.30]=449d2048fcb20a314d8c218097c6d1047a9f1c5bb72aa54d5d3eba0a27a4c80c
	[7.4.33]=5a2337996f07c8a097e03d46263b5c98d2c8e355227756351421003bea8f463e
)
# https://github.com/php/php-src/tree/PHP-<branch>-CVE-2026-109618-109619
declare -A BACKPORT_BASE=([7.4]=7.4.33 [8.0]=8.0.30 [8.1]=8.1.34)
declare -A BACKPORT_COMMIT=(
	[7.4]=712e60f9edfd03f0960fc4fc3c2c375f42b90aa2
	[8.0]=82f8f31b16a035c1b67cc253e79f7cc288f4cc20
	[8.1]=1d7dec178a094e6e75b229ce22754045f8c6070a
)
declare -A BACKPORT_SHA256=(
	[7.4]=5fe57ca6ee96d59b36c6e0ca842843c50884f177bef1e85234cf669b577f5e48
	[8.0]=534478c973cef6f493605b7af907f639a364912ee92c24598ddae44c3bc72d1c
	[8.1]=c85ad0fddcbff7f2318617eeaa54d271135463b5bf70a01228447e3ed78de96e
)

CHECK_ONLY=0
ASSUME_YES=0
ONLY_TAGS=""
JOBS=""
IS_TTY=0
SETUP_PATH=/www
PHP_ROOT=""
WORK_DIR=""
BACKUP_DIR=""
LOG_DIR=""
MAIN_LOG=/dev/null
CUR_LOG=/dev/null
RUN_ID=$(date +%Y%m%d-%H%M%S)
PKG_MANAGER=""
APT_UPDATED=0
DEPS_INSTALLED=0
PROBE_DIR=""
PROBE_PAGE=""
PROBE_CLIENT=""
BACKUP_FILE=""
PROBE_RESULT=""

CONF_ARGS=()
BUILD_ENV=()
MAKE_ARGS=()
PLAN_TAGS=()
declare -A PLAN_CUR PLAN_ACTION PLAN_TARGET PLAN_SHA PLAN_NOTE
declare -A RESULT_STATUS RESULT_AFTER RESULT_NOTE
declare -A RELEASE_CACHE

C_RED="" C_GREEN="" C_YELLOW="" C_CYAN="" C_BOLD="" C_DIM="" C_RESET=""

# ---------------------------------------------------------------- output ----

setup_colors() {
	[ "$IS_TTY" = 1 ] || return 0
	C_RED=$'\033[31m' C_GREEN=$'\033[32m' C_YELLOW=$'\033[33m' C_CYAN=$'\033[36m'
	C_BOLD=$'\033[1m' C_DIM=$'\033[2m' C_RESET=$'\033[0m'
}

info()  { printf '%s[資訊]%s %s\n' "$C_CYAN" "$C_RESET" "$*"; }
ok()    { printf '%s[成功]%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '%s[警告]%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
err()   { printf '%s[錯誤]%s %s\n' "$C_RED" "$C_RESET" "$*"; }
die()   { err "$*"; exit 1; }
title() { printf '\n%s━━ %s ━━%s\n' "$C_BOLD" "$*" "$C_RESET"; }

# Transient progress lines go to the terminal only, never into the log.
progress() { [ "$IS_TTY" = 1 ] && printf '\r\033[K  %s' "$*" >&3; }
progress_done() { [ "$IS_TTY" = 1 ] && printf '\r\033[K' >&3; }

banner() {
	printf '%s' "$C_BOLD"
	printf '══════════════════════════════════════════════════════════\n'
	printf '  寶塔 PHP 安全更新  v%s\n' "$SCRIPT_VERSION"
	printf '  修補 %s（PHP 遠端程式碼執行漏洞）\n' "$CVE_LABEL"
	printf '══════════════════════════════════════════════════════════\n'
	printf '%s' "$C_RESET"
	printf '%s  官方公告：%s%s\n' "$C_DIM" "$ADVISORY_URL" "$C_RESET"
}

usage() {
	cat <<EOF
寶塔 / aaPanel PHP 安全更新腳本 v${SCRIPT_VERSION}
修補 ${CVE_LABEL}（PHP 遠端程式碼執行漏洞）

用法：bash bt-php-security-update.sh [選項]

  --check        只檢查並列出處理計畫，不做任何變更
  --only 74,82   只處理指定的 PHP 版本目錄（以逗號分隔）
  --jobs N       編譯並行數（預設依 CPU 與記憶體自動決定）
  -y, --yes      不倒數，立即開始
  -h, --help     顯示本說明

處理方式：
  PHP 8.2 以上     升級到同系列最新版
  PHP 7.4/8.0/8.1  升級到該系列最後一版並套用 PHP 官方安全修補
  PHP 5.x ~ 7.3    官方沒有修補，套用緩解設定並列出仍在使用的網站

環境變數：
  PHP_MIRROR       額外的原始碼下載來源（需提供 php-X.Y.Z.tar.gz，一律校驗 SHA256）

結束代碼：0 完成或無需處理；1 有版本處理失敗；2 檢查模式下有版本需要處理
EOF
}

# --------------------------------------------------------------- helpers ----

ver_num() {
	local a b c
	IFS=. read -r a b c <<<"$1"
	c=${c%%[!0-9]*}
	printf '%d' $((10#${a:-0} * 1000000 + 10#${b:-0} * 1000 + 10#${c:-0}))
}

sha256_of() { sha256sum "$1" 2>/dev/null | awk '{print $1}'; }

free_mb() { df -Pm "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }

fetch_file() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 10 --retry 2 --retry-delay 2 \
			--speed-limit 1024 --speed-time 60 -o "$2" "$1"
	else
		wget -q -T 60 -t 3 -O "$2" "$1"
	fi
}

fetch_text() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --connect-timeout 8 -m 20 "$1"
	else
		wget -q -T 20 -t 2 -O - "$1"
	fi
}

show_log_tail() {
	printf '%s' "$C_DIM"
	tail -n 25 "$1" 2>/dev/null | sed 's/^/    /'
	printf '%s' "$C_RESET"
	info "完整記錄：$1"
}

set_result() { RESULT_STATUS[$1]=$2; RESULT_AFTER[$1]=$3; RESULT_NOTE[$1]=$4; }

fail_version() {
	err "PHP $1：$2"
	set_result "$1" fail "${PLAN_CUR[$1]}" "$2"
}

# ------------------------------------------------------------- preflight ----

parse_args() {
	while [ $# -gt 0 ]; do
		case "$1" in
			--check|--dry-run) CHECK_ONLY=1 ;;
			--only) shift; ONLY_TAGS=${1:-} ;;
			--only=*) ONLY_TAGS=${1#*=} ;;
			--jobs) shift; JOBS=${1:-} ;;
			--jobs=*) JOBS=${1#*=} ;;
			-y|--yes) ASSUME_YES=1 ;;
			-h|--help) usage; exit 0 ;;
			*) usage; die "未知的參數：$1" ;;
		esac
		shift
	done
	if [ -n "$JOBS" ] && ! [[ "$JOBS" =~ ^[1-9][0-9]{0,2}$ ]]; then
		die "--jobs 必須是正整數"
	fi
	if [ -n "$ONLY_TAGS" ] && ! [[ "$ONLY_TAGS" =~ ^[0-9]{2}(,[0-9]{2})*$ ]]; then
		die "--only 格式錯誤，範例：--only 74,82"
	fi
	if [ -n "${PHP_MIRROR:-}" ] && ! [[ "$PHP_MIRROR" =~ ^https?://[A-Za-z0-9._~:/%+-]+$ ]]; then
		die "PHP_MIRROR 格式錯誤：$PHP_MIRROR"
	fi
}

preflight() {
	[ "$(id -u)" = 0 ] || die "請使用 root 身分執行"
	[ "$(uname -s)" = Linux ] || die "只支援 Linux 伺服器"
	if [ -s /var/bt_setupPath.conf ]; then
		SETUP_PATH=$(head -n1 /var/bt_setupPath.conf | tr -d '[:space:]')
	fi
	SETUP_PATH=${SETUP_PATH:-/www}
	[[ "$SETUP_PATH" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "寶塔安裝路徑異常：$SETUP_PATH"
	SETUP_PATH=${SETUP_PATH%/}
	PHP_ROOT="$SETUP_PATH/server/php"
	WORK_DIR="$SETUP_PATH/server/php_security_update"
	BACKUP_DIR="$SETUP_PATH/backup/php_security_update"
	LOG_DIR="$BACKUP_DIR/logs"
	[ -d "$SETUP_PATH/server/panel" ] || die "找不到寶塔面板（$SETUP_PATH/server/panel），此腳本只適用於寶塔 / aaPanel"
	[ -d "$PHP_ROOT" ] || die "找不到 $PHP_ROOT，這台伺服器沒有透過寶塔安裝 PHP"
	if command -v apt-get >/dev/null 2>&1; then
		PKG_MANAGER=apt-get
	elif command -v dnf >/dev/null 2>&1; then
		PKG_MANAGER=dnf
	elif command -v yum >/dev/null 2>&1; then
		PKG_MANAGER=yum
	fi
}

setup_logging() {
	local d
	for d in "$WORK_DIR" "$BACKUP_DIR"; do
		[ -L "$d" ] && die "$d 是符號連結，為了安全已停止執行"
	done
	mkdir -p "$LOG_DIR" || die "無法建立 $LOG_DIR"
	chmod 700 "$BACKUP_DIR"
	MAIN_LOG="$LOG_DIR/update-$RUN_ID.log"
	exec > >(tee >(sed -u 's/\x1b\[[0-9;]*[A-Za-z]//g' >>"$MAIN_LOG")) 2>&1
}

acquire_lock() {
	local lock=/run/bt-php-security-update.lock
	[ -d /run ] || lock=/var/run/bt-php-security-update.lock
	command -v flock >/dev/null 2>&1 || return 0
	exec 9>"$lock"
	flock -n 9 || die "已有另一個 PHP 更新程序正在執行，請等它結束後再試"
}

install_packages() {
	local p
	case "$PKG_MANAGER" in
		apt-get)
			if [ "$APT_UPDATED" != 1 ]; then
				DEBIAN_FRONTEND=noninteractive apt-get update -qq </dev/null >>"$MAIN_LOG" 2>&1
				APT_UPDATED=1
			fi
			for p in "$@"; do
				DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$p" </dev/null >>"$MAIN_LOG" 2>&1
			done
			;;
		dnf|yum)
			for p in "$@"; do
				"$PKG_MANAGER" install -y -q "$p" </dev/null >>"$MAIN_LOG" 2>&1
			done
			;;
		*) return 1 ;;
	esac
	return 0
}

ensure_build_tools() {
	local need_patch=$1 c pkgs=() missing=()
	command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || pkgs+=(curl)
	for c in tar gzip make gcc patch; do
		[ "$c" = patch ] && [ "$need_patch" != 1 ] && continue
		command -v "$c" >/dev/null 2>&1 || pkgs+=("$c")
	done
	if ! command -v g++ >/dev/null 2>&1; then
		if [ "$PKG_MANAGER" = apt-get ]; then pkgs+=(g++); else pkgs+=(gcc-c++); fi
	fi
	if [ ${#pkgs[@]} -gt 0 ]; then
		info "安裝缺少的編譯工具：${pkgs[*]}"
		install_packages "${pkgs[@]}" || warn "無法辨識套件管理工具，請手動安裝：${pkgs[*]}"
	fi
	command -v curl >/dev/null 2>&1 || command -v wget >/dev/null 2>&1 || missing+=(curl)
	for c in tar gzip make gcc sha256sum base64; do
		command -v "$c" >/dev/null 2>&1 || missing+=("$c")
	done
	[ "$need_patch" = 1 ] && ! command -v patch >/dev/null 2>&1 && missing+=(patch)
	[ ${#missing[@]} -eq 0 ] || die "缺少必要工具：${missing[*]}，請手動安裝後再執行"
}

install_build_deps() {
	[ "$DEPS_INSTALLED" = 1 ] && return 1
	DEPS_INSTALLED=1
	info "安裝常用的 PHP 編譯相依套件（需要幾分鐘）…"
	case "$PKG_MANAGER" in
		apt-get)
			install_packages gcc g++ make pkg-config patch libxml2-dev libsqlite3-dev \
				libcurl4-openssl-dev libonig-dev libssl-dev zlib1g-dev libpng-dev libjpeg-dev \
				libfreetype6-dev libwebp-dev libicu-dev libsodium-dev libzip-dev libxslt1-dev \
				libbz2-dev libgmp-dev libreadline-dev libc-ares-dev
			;;
		dnf|yum)
			install_packages gcc gcc-c++ make pkgconfig patch libxml2-devel sqlite-devel \
				libcurl-devel oniguruma-devel openssl-devel zlib-devel libpng-devel \
				libjpeg-turbo-devel freetype-devel libwebp-devel libicu-devel libsodium-devel \
				libzip-devel libxslt-devel bzip2-devel gmp-devel readline-devel c-ares-devel
			;;
		*) return 1 ;;
	esac
}

decide_jobs() {
	local cpu mem
	cpu=$(nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo)
	cpu=${cpu:-1}
	mem=$(awk '/^MemAvailable:/ {a=$2} /^MemFree:/ {f=$2} /^Cached:/ {c=$2} /^SwapFree:/ {s=$2}
		END {if (!a) a = f + c; print int((a + s) / 1024)}' /proc/meminfo 2>/dev/null)
	mem=${mem:-0}
	if [ "$mem" -lt 1024 ]; then
		warn "可用記憶體（含 Swap）只有 ${mem}MB，編譯可能失敗，建議先增加 Swap 再執行"
	fi
	[ -n "$JOBS" ] && return 0
	JOBS=$((mem / 1024))
	[ "$JOBS" -lt 1 ] && JOBS=1
	[ "$JOBS" -gt "$cpu" ] && JOBS=$cpu
}

# ------------------------------------------------------------------ plan ----

php_version_of() {
	local v
	v=$("$1/bin/php" -n -r 'echo PHP_VERSION;' 2>/dev/null </dev/null)
	if ! [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+ ]]; then
		v=$(head -n1 "$1/version.pl" 2>/dev/null | tr -d '[:space:]')
	fi
	[[ "$v" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]] && printf '%s' "${BASH_REMATCH[1]}"
}

# Sets REL_VERSION / REL_SHA to the newest php.net release of a branch.
resolve_release() {
	local branch=$1 json ver sha fixed
	if [ -n "${RELEASE_CACHE[$branch]:-}" ]; then
		read -r REL_VERSION REL_SHA <<<"${RELEASE_CACHE[$branch]}"
		return 0
	fi
	REL_VERSION="" REL_SHA=""
	json=$(fetch_text "https://www.php.net/releases/index.php?json&version=${branch}" 2>/dev/null)
	ver=$(printf '%s' "$json" | grep -o '"version":"[0-9]*\.[0-9]*\.[0-9]*"' | head -n1 | cut -d'"' -f4)
	if [ -n "$ver" ] && [ "${ver%.*}" = "$branch" ]; then
		sha=$(printf '%s' "$json" | tr '{}' '\n\n' | grep "\"filename\":\"php-${ver}\.tar\.gz\"" |
			grep -o '"sha256":"[0-9a-f]\{64\}"' | head -n1 | cut -d'"' -f4)
	fi
	fixed=${FIXED_RELEASE[$branch]:-}
	if [ -n "$ver" ] && [ -n "$sha" ] && { [ -z "$fixed" ] || [ "$(ver_num "$ver")" -ge "$(ver_num "$fixed")" ]; }; then
		REL_VERSION=$ver REL_SHA=$sha
	elif [ -n "$fixed" ]; then
		REL_VERSION=$fixed REL_SHA=${KNOWN_SHA256[$fixed]}
	fi
	[ -n "$REL_VERSION" ] && RELEASE_CACHE[$branch]="$REL_VERSION $REL_SHA"
}

upload_progress_state() {
	local ver=$1 ini=$2
	if [ "$(ver_num "$ver")" -lt "$(ver_num 5.4.0)" ]; then
		echo na
		return
	fi
	[ -f "$ini" ] || { echo on; return; }
	awk -F= '
		BEGIN { v = "on" }
		$1 ~ /^[ \t]*session\.upload_progress\.enabled[ \t]*$/ {
			x = $2; sub(/;.*/, "", x); gsub(/[ \t"]/, "", x); x = tolower(x)
			v = (x == "off" || x == "0" || x == "false" || x == "no" || x == "none" || x == "") ? "off" : "on"
		}
		END { print v }' "$ini"
}

build_plan() {
	local dir tag cur branch target state
	for dir in "$PHP_ROOT"/[0-9][0-9]; do
		[ -d "$dir" ] && [ -x "$dir/bin/php" ] || continue
		tag=${dir##*/}
		if [ -n "$ONLY_TAGS" ] && [[ ",$ONLY_TAGS," != *",$tag,"* ]]; then
			continue
		fi
		cur=$(php_version_of "$dir")
		PLAN_TAGS+=("$tag")
		PLAN_CUR[$tag]=${cur:-未知}
		if [ -z "$cur" ]; then
			PLAN_ACTION[$tag]=skip PLAN_NOTE[$tag]="無法取得版本，略過"
			continue
		fi
		branch=${cur%.*}

		if [ -n "${BACKPORT_BASE[$branch]:-}" ]; then
			target=${BACKPORT_BASE[$branch]}
			if [ "$cur" = "$target" ] && [ -f "$dir/$PATCH_MARKER" ]; then
				PLAN_ACTION[$tag]=ok PLAN_NOTE[$tag]="已套用官方安全修補"
			elif [ "$(ver_num "$cur")" -gt "$(ver_num "$target")" ]; then
				PLAN_ACTION[$tag]=skip PLAN_NOTE[$tag]="非官方版本號，無法判斷，請手動確認"
			else
				PLAN_ACTION[$tag]=backport PLAN_TARGET[$tag]=$target PLAN_SHA[$tag]=${KNOWN_SHA256[$target]}
				if [ "$cur" = "$target" ]; then
					PLAN_NOTE[$tag]="重新編譯並套用官方安全修補"
				else
					PLAN_NOTE[$tag]="升級到 $target 並套用官方安全修補"
				fi
			fi
		elif [ "$(ver_num "$cur")" -lt "$(ver_num 7.4.0)" ]; then
			state=$(upload_progress_state "$cur" "$dir/etc/php.ini")
			case "$state" in
				na)  PLAN_ACTION[$tag]=warn PLAN_NOTE[$tag]="官方沒有修補，也沒有可用的緩解設定，請盡快改用 8.2 以上" ;;
				off) PLAN_ACTION[$tag]=mitigated PLAN_NOTE[$tag]="已套用緩解設定，但官方沒有修補，仍有風險" ;;
				*)   PLAN_ACTION[$tag]=mitigate PLAN_NOTE[$tag]="官方沒有修補，套用緩解設定" ;;
			esac
		else
			resolve_release "$branch"
			if [ -z "$REL_VERSION" ]; then
				PLAN_ACTION[$tag]=skip PLAN_NOTE[$tag]="無法取得 PHP $branch 的版本資訊（請確認能連線到 php.net）"
			elif [ "$(ver_num "$cur")" -ge "$(ver_num "$REL_VERSION")" ]; then
				PLAN_ACTION[$tag]=ok PLAN_NOTE[$tag]="已是最新版本"
			else
				PLAN_ACTION[$tag]=upgrade PLAN_TARGET[$tag]=$REL_VERSION PLAN_SHA[$tag]=$REL_SHA
				PLAN_NOTE[$tag]="升級到 $REL_VERSION"
			fi
		fi
	done
}

print_plan() {
	local tag color
	title "已安裝的 PHP 版本"
	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			ok) color=$C_GREEN ;;
			upgrade|backport|mitigate) color=$C_YELLOW ;;
			*) color=$C_RED ;;
		esac
		printf '  PHP %-3s  %-8s  %s%s%s\n' "$tag" "${PLAN_CUR[$tag]}" "$color" "${PLAN_NOTE[$tag]}" "$C_RESET"
	done
}

sites_using() {
	local tag=$1 f list=()
	for f in "$SETUP_PATH"/server/panel/vhost/nginx/*.conf; do
		[ -f "$f" ] && grep -qE "enable-php-${tag}(-wpfastcgi)?\.conf" "$f" && list+=("$(basename "$f" .conf)")
	done
	for f in "$SETUP_PATH"/server/panel/vhost/apache/*.conf; do
		[ -f "$f" ] && grep -q "php-cgi-${tag}\.sock" "$f" && list+=("$(basename "$f" .conf)")
	done
	[ ${#list[@]} -gt 0 ] && printf '%s\n' "${list[@]}" | sort -u | paste -sd ' ' -
}

# ------------------------------------------------------------- php-fpm -----

fpm_pid_file() {
	local p
	p=$(sed -n 's/^[[:space:]]*pid[[:space:]]*=[[:space:]]*//p' "$1/etc/php-fpm.conf" 2>/dev/null | head -n1 | tr -d '[:space:]"')
	p=${p:-run/php-fpm.pid}
	[ "${p#/}" = "$p" ] && p="$1/var/$p"
	printf '%s' "$p"
}

fpm_master_pid() {
	local f pid
	f=$(fpm_pid_file "$1")
	if [ -s "$f" ]; then
		pid=$(tr -cd '0-9' <"$f")
		if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
			printf '%s' "$pid"
			return 0
		fi
	fi
	pid=$(pgrep -o -f "php-fpm: master process \\($1/" 2>/dev/null)
	[ -n "$pid" ] && printf '%s' "$pid"
}

fpm_listen() {
	local conf="$1/etc/php-fpm.conf" files=() inc f
	[ -f "$conf" ] || return 0
	files+=("$conf")
	while read -r inc; do
		inc=${inc//\"/}
		[ "${inc#/}" = "$inc" ] && inc="$1/$inc"
		for f in $inc; do
			[ -f "$f" ] && files+=("$f")
		done
	done < <(sed -n 's/^[[:space:]]*include[[:space:]]*=[[:space:]]*//p' "$conf")
	sed -n 's/^[[:space:]]*listen[[:space:]]*=[[:space:]]*//p' "${files[@]}" 2>/dev/null | head -n1 | tr -d '[:space:]"'
}

# fd 3 (terminal) and 9 (lock) are closed so the daemon does not inherit them.
fpm_service() {
	local unit="php-fpm-$1.service"
	if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet "$unit" 2>/dev/null; then
		systemctl "$2" "$unit" 3>&- 9>&-
	elif [ -x "/etc/init.d/php-fpm-$1" ]; then
		"/etc/init.d/php-fpm-$1" "$2" 3>&- 9>&-
	elif command -v systemctl >/dev/null 2>&1 && systemctl cat "$unit" >/dev/null 2>&1; then
		systemctl "$2" "$unit" 3>&- 9>&-
	else
		return 127
	fi
}

fpm_force_restart() {
	local tag=$1 prefix=$2 pid i
	pid=$(fpm_master_pid "$prefix")
	if [ -n "$pid" ]; then
		kill -TERM "$pid" 2>/dev/null
		for i in $(seq 1 20); do
			kill -0 "$pid" 2>/dev/null || break
			sleep 0.5
		done
		kill -0 "$pid" 2>/dev/null && kill -KILL "$pid" 2>/dev/null
		sleep 1
	fi
	fpm_service "$tag" start </dev/null >>"$CUR_LOG" 2>&1
}

setup_probe() {
	PROBE_DIR="$WORK_DIR/probe"
	mkdir -p "$PROBE_DIR" || return 1
	chmod 755 "$WORK_DIR" "$PROBE_DIR"
	PROBE_PAGE="$PROBE_DIR/bt_probe_${RANDOM}${RANDOM}.php"
	printf '%s\n' '<?php echo "BTPROBE|", PHP_VERSION, "|", (int) (bool) ini_get("session.upload_progress.enabled"), "|";' >"$PROBE_PAGE"
	chmod 644 "$PROBE_PAGE"
	PROBE_CLIENT="$PROBE_DIR/fcgi_client.php"
	cat >"$PROBE_CLIENT" <<'PHP'
<?php
// Minimal FastCGI client (PHP 5.2+): one GET request for argv[2] to listener argv[1].
function fcgi_record($type, $content)
{
    return pack('CCnnCx', 1, $type, 1, strlen($content), 0) . $content;
}

function fcgi_length($len)
{
    return $len < 128 ? chr($len) : pack('N', $len | 0x80000000);
}

function fcgi_read($fp, $len)
{
    $buf = '';
    while (strlen($buf) < $len) {
        $chunk = fread($fp, $len - strlen($buf));
        if ($chunk === false || $chunk === '') {
            break;
        }
        $buf .= $chunk;
    }
    return $buf;
}

$listen = $argv[1];
$script = $argv[2];
if ($listen[0] === '/') {
    $remote = 'unix://' . $listen;
} elseif (strpos($listen, ':') === false) {
    $remote = 'tcp://127.0.0.1:' . $listen;
} else {
    $pos = strrpos($listen, ':');
    $host = substr($listen, 0, $pos);
    if ($host === '' || $host === '*' || $host === '0.0.0.0' || $host === '[::]') {
        $host = '127.0.0.1';
    }
    $remote = 'tcp://' . $host . substr($listen, $pos);
}

$fp = @stream_socket_client($remote, $errno, $errstr, 5);
if (!$fp) {
    fwrite(STDERR, "connect failed: $errstr\n");
    exit(2);
}
stream_set_timeout($fp, 20);

$name = '/' . basename($script);
$params = array(
    'GATEWAY_INTERFACE' => 'CGI/1.1',
    'SERVER_SOFTWARE' => 'bt-php-security-update',
    'SERVER_PROTOCOL' => 'HTTP/1.1',
    'SERVER_NAME' => 'localhost',
    'SERVER_ADDR' => '127.0.0.1',
    'SERVER_PORT' => '80',
    'REMOTE_ADDR' => '127.0.0.1',
    'REQUEST_METHOD' => 'GET',
    'REQUEST_URI' => $name,
    'QUERY_STRING' => '',
    'DOCUMENT_ROOT' => dirname($script),
    'SCRIPT_NAME' => $name,
    'SCRIPT_FILENAME' => $script,
);
$body = '';
foreach ($params as $key => $value) {
    $body .= fcgi_length(strlen($key)) . fcgi_length(strlen($value)) . $key . $value;
}
fwrite($fp, fcgi_record(1, pack('nCx5', 1, 0)) . fcgi_record(4, $body) . fcgi_record(4, '') . fcgi_record(5, ''));

$out = '';
$ended = false;
while (!$ended) {
    $header = fcgi_read($fp, 8);
    if (strlen($header) < 8) {
        break;
    }
    $rec = unpack('Cversion/Ctype/nid/nlength/Cpadding/Creserved', $header);
    $data = fcgi_read($fp, $rec['length'] + $rec['padding']);
    if ($rec['type'] == 6) {
        $out .= substr($data, 0, $rec['length']);
    } elseif ($rec['type'] == 3) {
        $ended = true;
    }
}
fclose($fp);
echo $out;
exit($ended ? 0 : 1);
PHP
	chmod 600 "$PROBE_CLIENT"
}

# Sends a real request through PHP-FPM; sets PROBE_RESULT to "version|upload_progress".
probe_fpm() {
	local prefix=$1 listen out i
	PROBE_RESULT=""
	listen=$(fpm_listen "$prefix")
	[ -n "$listen" ] || return 2
	for i in 1 2 3 4 5 6; do
		out=$("$prefix/bin/php" -n "$PROBE_CLIENT" "$listen" "$PROBE_PAGE" 2>>"$CUR_LOG" </dev/null)
		if [ -n "$out" ]; then
			if [[ "$out" =~ BTPROBE[|]([0-9.]+)[|]([01])[|] ]]; then
				PROBE_RESULT="${BASH_REMATCH[1]}|${BASH_REMATCH[2]}"
				return 0
			fi
			printf '%s\n' "$out" | head -n 5 >>"$CUR_LOG"
			return 3
		fi
		sleep 1
	done
	return 1
}

# Confirms the running FPM master uses the binary on disk and actually serves requests.
verify_fpm() {
	local tag=$1 prefix=$2 expect=$3 pid exe want i rc
	for i in $(seq 1 20); do
		pid=$(fpm_master_pid "$prefix")
		[ -n "$pid" ] && break
		sleep 0.5
	done
	if [ -z "$pid" ]; then
		err "PHP-FPM $tag 沒有成功啟動"
		return 1
	fi
	exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
	want=$(readlink -f "$prefix/sbin/php-fpm")
	if [ -n "$exe" ] && [ "$exe" != "$want" ]; then
		err "PHP-FPM $tag 仍在使用舊的程式檔（$exe）"
		return 1
	fi
	probe_fpm "$prefix"
	rc=$?
	case $rc in
		0)
			if [ "${PROBE_RESULT%%|*}" != "$expect" ]; then
				err "PHP-FPM 回應的版本是 ${PROBE_RESULT%%|*}，預期為 $expect"
				return 1
			fi
			ok "實際請求測試通過：PHP-FPM $tag 正常回應，版本 ${PROBE_RESULT%%|*}"
			;;
		2) warn "找不到 PHP-FPM $tag 的監聽位址，略過請求測試" ;;
		3) warn "PHP-FPM $tag 有回應，但無法執行測試頁（可能有 chroot 或安全限制），略過版本比對" ;;
		*)
			err "PHP-FPM $tag 沒有回應請求"
			return 1
			;;
	esac
	return 0
}

restart_and_verify() {
	local tag=$1 prefix=$2 expect=$3
	fpm_service "$tag" restart </dev/null >>"$CUR_LOG" 2>&1
	verify_fpm "$tag" "$prefix" "$expect" && return 0
	warn "改用強制重啟再試一次…"
	fpm_force_restart "$tag" "$prefix"
	verify_fpm "$tag" "$prefix" "$expect"
}

# ----------------------------------------------------------------- build ----

source_urls() {
	local v=$1
	[ -n "${PHP_MIRROR:-}" ] && printf '%s\n' "${PHP_MIRROR%/}/php-$v.tar.gz"
	if grep -qs '"English"' "$SETUP_PATH/server/panel/config/config.json"; then
		printf '%s\n' "https://www.php.net/distributions/php-$v.tar.gz" \
			"https://node.aapanel.com/src/php-$v.tar.gz" "https://download.bt.cn/src/php-$v.tar.gz"
	else
		printf '%s\n' "https://download.bt.cn/src/php-$v.tar.gz" \
			"https://www.php.net/distributions/php-$v.tar.gz" "https://node.aapanel.com/src/php-$v.tar.gz"
	fi
}

download_source() {
	local ver=$1 sha=$2 dest=$3 url
	if [ -f "$dest" ] && [ "$(sha256_of "$dest")" = "$sha" ]; then
		return 0
	fi
	while read -r url; do
		info "下載 $url"
		rm -f "$dest.part"
		if fetch_file "$url" "$dest.part" 2>>"$CUR_LOG"; then
			if [ "$(sha256_of "$dest.part")" = "$sha" ]; then
				mv -f "$dest.part" "$dest"
				ok "下載完成，SHA256 校驗正確"
				return 0
			fi
			warn "檔案校驗不符（可能被竄改或不完整），已丟棄，改用下一個來源"
		else
			warn "下載失敗，改用下一個來源"
		fi
	done < <(source_urls "$ver")
	rm -f "$dest.part"
	return 1
}

apply_backport() {
	local branch=$1 dir=$2 pf="$WORK_DIR/php-$1-security.patch"
	"backport_blob_${branch/./}" | base64 -d | gzip -dc >"$pf" 2>>"$CUR_LOG"
	if [ "$(sha256_of "$pf")" != "${BACKPORT_SHA256[$branch]}" ]; then
		err "內建修補檔校驗失敗，腳本可能已損毀，請重新下載"
		return 1
	fi
	if ! patch -p1 -d "$dir" --forward --batch <"$pf" >>"$CUR_LOG" 2>&1; then
		err "修補檔套用失敗"
		return 1
	fi
	ok "已套用 PHP 官方安全修補（commit ${BACKPORT_COMMIT[$branch]:0:12}）"
}

read_configure_args() {
	local prefix=$1 raw a found=0
	CONF_ARGS=()
	raw=$("$prefix/bin/php" -n -i 2>/dev/null </dev/null | sed -n 's/^Configure Command =>[[:space:]]*//p' | head -n1)
	if [ -n "$raw" ]; then
		while IFS= read -r a; do
			[ -n "$a" ] && CONF_ARGS+=("$a")
		done < <(printf '%s\n' "$raw" | xargs -n1 printf '%s\n' 2>/dev/null)
		[[ "${CONF_ARGS[0]:-}" == *configure ]] && CONF_ARGS=("${CONF_ARGS[@]:1}")
	fi
	if [ ${#CONF_ARGS[@]} -eq 0 ] && [ -x "$prefix/bin/php-config" ]; then
		read -r -a CONF_ARGS <<<"$("$prefix/bin/php-config" --configure-options 2>/dev/null)"
	fi
	for a in "${CONF_ARGS[@]}"; do
		[ "$a" = "--prefix=$prefix" ] && found=1
	done
	if [ "$found" != 1 ]; then
		err "原本的編譯參數中找不到 --prefix=$prefix，為避免裝錯位置已停止"
		return 1
	fi
}

# Reuses the compiler that built the existing binary (e.g. gcc-13 on Debian 13, devtoolset on EL7).
detect_toolchain() {
	local prefix=$1 bin a used default cand cc="" cxx
	BUILD_ENV=() MAKE_ARGS=()
	bin="$prefix/sbin/php-fpm"
	[ -f "$bin" ] || bin="$prefix/bin/php"
	ldd "$bin" 2>/dev/null | grep -q 'libiconv\.so' && MAKE_ARGS+=("ZEND_EXTRA_LIBS=-liconv")
	for a in "${CONF_ARGS[@]}"; do
		[[ "$a" == CC=* ]] && return 0
	done
	used=$({ readelf -p .comment "$bin" 2>/dev/null || grep -a -o 'GCC: ([^)]*) [0-9][0-9.]*' "$bin" 2>/dev/null; } |
		sed -n 's/.*GCC: ([^)]*) \([0-9][0-9]*\)\..*/\1/p' | sort -n | tail -n1)
	default=$(gcc -dumpversion 2>/dev/null | cut -d. -f1)
	if [ -z "$used" ] || [ "$used" = "$default" ]; then
		return 0
	fi
	for cand in "gcc-$used" "/opt/rh/devtoolset-$used/root/usr/bin/gcc" "/opt/rh/gcc-toolset-$used/root/usr/bin/gcc"; do
		cc=$(command -v "$cand" 2>/dev/null) && break
	done
	if [ -z "$cc" ]; then
		info "原本使用 GCC $used 編譯，系統上找不到同版本，改用預設的 GCC $default"
		return 0
	fi
	cxx="${cc%gcc*}g++${cc##*gcc}"
	BUILD_ENV+=("CC=$cc")
	[ -x "$cxx" ] && BUILD_ENV+=("CXX=$cxx")
	case "$cc" in
		/opt/rh/*) BUILD_ENV+=("PATH=${cc%/gcc}:$PATH") ;;
	esac
	info "沿用原本的編譯器：$cc"
}

run_configure() {
	(cd "$1" && env "${BUILD_ENV[@]}" ./configure "${CONF_ARGS[@]}") </dev/null >>"$CUR_LOG" 2>&1
}

run_make() {
	local dir=$1 total objs pct start elapsed pid rc last_note=0
	total=$(grep -cE '^[^[:space:]]+\.lo:' "$dir/Makefile" 2>/dev/null)
	start=$SECONDS
	(cd "$dir" && env "${BUILD_ENV[@]}" make -j"$JOBS" "${MAKE_ARGS[@]}") </dev/null >>"$CUR_LOG" 2>&1 &
	pid=$!
	while kill -0 "$pid" 2>/dev/null; do
		sleep 3
		elapsed=$((SECONDS - start))
		if [ "$IS_TTY" = 1 ]; then
			if [ "${total:-0}" -gt 0 ]; then
				objs=$(find "$dir" -name '*.lo' 2>/dev/null | wc -l)
				pct=$((objs * 100 / total))
				[ "$pct" -gt 99 ] && pct=99
				progress "$(printf '編譯中 %3d%%　已經過 %d 分 %02d 秒' "$pct" $((elapsed / 60)) $((elapsed % 60)))"
			else
				progress "$(printf '編譯中…已經過 %d 分 %02d 秒' $((elapsed / 60)) $((elapsed % 60)))"
			fi
		elif [ $((elapsed - last_note)) -ge 120 ]; then
			last_note=$elapsed
			info "仍在編譯中…已經過 $((elapsed / 60)) 分鐘"
		fi
	done
	wait "$pid"
	rc=$?
	progress_done
	elapsed=$((SECONDS - start))
	[ "$rc" = 0 ] && info "編譯完成，耗時 $((elapsed / 60)) 分 $((elapsed % 60)) 秒"
	return "$rc"
}

list_modules() {
	"$1" -c "$2" -m 2>/dev/null </dev/null | grep -E '^[A-Za-z][A-Za-z0-9_ ]*$' | sort -u
}

# Validates the staged build against the live php.ini / php-fpm.conf before touching anything.
preflight_staged() {
	local prefix=$1 staged=$2 ini="$1/etc/php.ini" before after missing out
	before=$(list_modules "$prefix/bin/php" "$ini")
	after=$(list_modules "$staged/bin/php" "$ini")
	missing=$(comm -23 <(printf '%s\n' "$before") <(printf '%s\n' "$after") | paste -sd ' ' -)
	if [ -n "$missing" ]; then
		err "新版本載入擴充失敗：$missing"
		return 1
	fi
	ok "擴充模組檢查通過（$(printf '%s\n' "$after" | grep -c .) 個模組全部正常載入）"
	if [ -x "$staged/sbin/php-fpm" ] && [ -f "$prefix/etc/php-fpm.conf" ]; then
		if ! out=$("$staged/sbin/php-fpm" -t -y "$prefix/etc/php-fpm.conf" -c "$ini" 2>&1 </dev/null); then
			if "$prefix/sbin/php-fpm" -t -y "$prefix/etc/php-fpm.conf" -c "$ini" >/dev/null 2>&1 </dev/null; then
				err "新版本的 PHP-FPM 設定檢查失敗："
				printf '%s\n' "$out" | tail -n 5 | sed 's/^/    /'
				return 1
			fi
			warn "PHP-FPM 設定檢查原本就未通過，略過此項"
		else
			ok "PHP-FPM 設定檢查通過"
		fi
	fi
}

backup_install() {
	local tag=$1 cur=$2 rc
	BACKUP_FILE="$BACKUP_DIR/php$tag-$cur-$RUN_ID.tar.gz"
	info "備份目前的 PHP $tag → $BACKUP_FILE"
	tar -czf "$BACKUP_FILE" -C "$PHP_ROOT" --exclude="$tag/src" --exclude="$tag/src.tar.gz" \
		--exclude="$tag/var/log/*" --exclude="$tag/var/run/*" "$tag" 2>>"$CUR_LOG"
	rc=$?
	if [ "$rc" -gt 1 ] || ! gzip -t "$BACKUP_FILE" 2>/dev/null; then
		rm -f "$BACKUP_FILE"
		return 1
	fi
	chmod 600 "$BACKUP_FILE"
	ls -1t "$BACKUP_DIR"/php"$tag"-*.tar.gz 2>/dev/null | tail -n +4 | xargs -r rm -f --
}

restore_backup() {
	local tag=$1 prefix=$2 was_running=$3
	warn "正在從備份還原 PHP $tag…"
	[ "$was_running" = 1 ] && fpm_service "$tag" stop </dev/null >>"$CUR_LOG" 2>&1
	if ! tar -xzf "$BACKUP_FILE" -C "$PHP_ROOT" 2>>"$CUR_LOG"; then
		err "自動還原失敗！請手動執行：tar -xzf $BACKUP_FILE -C $PHP_ROOT"
		return 1
	fi
	if [ "$was_running" = 1 ]; then
		fpm_service "$tag" start </dev/null >>"$CUR_LOG" 2>&1
		if [ -z "$(fpm_master_pid "$prefix")" ]; then
			err "已還原檔案，但 PHP-FPM $tag 無法啟動，請手動執行：/etc/init.d/php-fpm-$tag start"
			return 1
		fi
	fi
	ok "已還原為原本的版本，網站不受影響"
}

swap_install() {
	local tag=$1 prefix=$2 staged=$3 target=$4 was_running=0 rc=0 cli
	[ -n "$(fpm_master_pid "$prefix")" ] && was_running=1
	trap '' INT TERM HUP PIPE
	info "替換為新版本…"
	if ! cp -a --remove-destination "$staged/." "$prefix/" 2>>"$CUR_LOG"; then
		err "檔案替換失敗"
		rc=1
	elif [ "$was_running" = 1 ]; then
		info "重新啟動 PHP-FPM $tag…"
		restart_and_verify "$tag" "$prefix" "$target" || rc=1
	else
		info "PHP-FPM $tag 原本沒有在執行，維持停止狀態"
	fi
	if [ "$rc" = 0 ]; then
		cli=$("$prefix/bin/php" -n -r 'echo PHP_VERSION;' 2>/dev/null </dev/null)
		if [ "$cli" != "$target" ]; then
			err "命令列 PHP 版本為 ${cli:-無法執行}，預期為 $target"
			rc=1
		fi
	fi
	[ "$rc" = 0 ] || restore_backup "$tag" "$prefix" "$was_running"
	trap - INT TERM HUP PIPE
	return "$rc"
}

finalize_install() {
	local tag=$1 prefix=$2 target=$3 mode=$4 tarball=$5
	printf '%s\n' "$target" >"$prefix/version.pl"
	rm -f "$prefix/version_check.pl"
	if [ "$mode" = backport ]; then
		printf 'fixed=%s\nbase=%s\ncommit=%s\ndate=%s\n' "$CVE_LABEL" "$target" \
			"${BACKPORT_COMMIT[${target%.*}]}" "$(date '+%F %T')" >"$prefix/$PATCH_MARKER"
	else
		rm -f "$prefix/$PATCH_MARKER"
	fi
	[ -f "$prefix/src.tar.gz" ] && cp -f "$tarball" "$prefix/src.tar.gz"
}

process_build() {
	local tag=$1 mode=$2
	local prefix="$PHP_ROOT/$tag" cur=${PLAN_CUR[$1]} target=${PLAN_TARGET[$1]} sha=${PLAN_SHA[$1]}
	local build="$WORK_DIR/build-$tag" stage="$WORK_DIR/stage-$tag"
	local tarball="$WORK_DIR/php-$target.tar.gz" label=$target staged built free
	CUR_LOG="$LOG_DIR/php$tag-build-$RUN_ID.log"
	[ "$mode" = backport ] && label="$target + 官方安全修補"
	title "PHP $tag：$cur → $label"

	free=$(free_mb "$SETUP_PATH")
	if [ "${free:-0}" -lt "$MIN_FREE_MB" ]; then
		fail_version "$tag" "磁碟空間不足（剩 ${free:-?}MB，至少需要 ${MIN_FREE_MB}MB）"
		return 1
	fi
	download_source "$target" "$sha" "$tarball" || { fail_version "$tag" "原始碼下載失敗，請確認伺服器能連上 php.net 或 bt.cn"; return 1; }

	rm -rf "$build" "$stage"
	mkdir -p "$build"
	if ! tar -xzf "$tarball" -C "$build" --strip-components=1 2>>"$CUR_LOG"; then
		fail_version "$tag" "原始碼解壓縮失敗"
		return 1
	fi
	if [ "$mode" = backport ] && ! apply_backport "${target%.*}" "$build"; then
		fail_version "$tag" "安全修補套用失敗"
		return 1
	fi
	read_configure_args "$prefix" || { fail_version "$tag" "無法取得原本的編譯參數"; return 1; }
	detect_toolchain "$prefix"

	info "沿用原本的編譯參數執行 configure…"
	if ! run_configure "$build" && ! { install_build_deps && run_configure "$build"; }; then
		show_log_tail "$CUR_LOG"
		fail_version "$tag" "configure 失敗（線上版本沒有任何變動）"
		return 1
	fi
	info "開始編譯（並行數 $JOBS，通常需要 5～20 分鐘）"
	if ! run_make "$build"; then
		show_log_tail "$CUR_LOG"
		fail_version "$tag" "編譯失敗（線上版本沒有任何變動）"
		return 1
	fi
	if ! env "${BUILD_ENV[@]}" make -C "$build" install INSTALL_ROOT="$stage" </dev/null >>"$CUR_LOG" 2>&1; then
		show_log_tail "$CUR_LOG"
		fail_version "$tag" "安裝到暫存目錄失敗（線上版本沒有任何變動）"
		return 1
	fi
	staged="$stage$prefix"
	built=$("$staged/bin/php" -n -r 'echo PHP_VERSION;' 2>/dev/null </dev/null)
	if [ "$built" != "$target" ]; then
		fail_version "$tag" "編譯結果版本為 ${built:-無法執行}，與預期 $target 不符"
		return 1
	fi
	preflight_staged "$prefix" "$staged" || { fail_version "$tag" "新版本檢查未通過，已取消替換（線上版本沒有任何變動）"; return 1; }
	backup_install "$tag" "$cur" || { fail_version "$tag" "備份失敗，已取消替換"; return 1; }

	if ! swap_install "$tag" "$prefix" "$staged" "$target"; then
		fail_version "$tag" "新版本啟動驗證失敗，已自動還原為 $cur"
		return 1
	fi
	finalize_install "$tag" "$prefix" "$target" "$mode" "$tarball"
	rm -rf "$build" "$stage" "$tarball"
	if [ "$mode" = backport ]; then
		ok "PHP $tag 已更新為 $target 並套用官方安全修補"
		set_result "$tag" patched "$target" "已套用官方安全修補"
	else
		ok "PHP $tag 已升級為 $target"
		set_result "$tag" upgraded "$target" "已升級"
	fi
}

process_mitigation() {
	local tag=$1 prefix="$PHP_ROOT/$1" ini="$PHP_ROOT/$1/etc/php.ini" cur=${PLAN_CUR[$1]} f
	local key='^[[:space:]]*;?[[:space:]]*session\.upload_progress\.enabled[[:space:]]*='
	CUR_LOG="$LOG_DIR/php$tag-mitigation-$RUN_ID.log"
	title "PHP $tag（$cur）：套用緩解設定"
	warn "PHP $cur 已停止維護，官方沒有修補；緩解設定只能擋下已知的攻擊路徑"
	if [ ! -f "$ini" ]; then
		fail_version "$tag" "找不到 $ini"
		return 1
	fi
	cp -p "$ini" "$BACKUP_DIR/php$tag-php.ini-$RUN_ID.bak"
	if grep -qE "$key" "$ini"; then
		sed -i -E "s/${key}.*$/session.upload_progress.enabled = Off/" "$ini"
	elif grep -q '^\[Session\]' "$ini"; then
		sed -i '/^\[Session\]/a session.upload_progress.enabled = Off' "$ini"
	else
		sed -i '1i session.upload_progress.enabled = Off' "$ini"
	fi
	ok "已在 php.ini 設定 session.upload_progress.enabled = Off（原檔備份於 $BACKUP_DIR）"
	for f in "$prefix/etc/php-fpm.conf" "$prefix"/etc/php-fpm.d/*.conf; do
		[ -f "$f" ] || continue
		if grep -qiE 'php_(admin_)?(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=[[:space:]]*(on|1|true|yes)' "$f"; then
			warn "$f 內的設定會重新開啟 upload_progress，請手動移除該行"
		fi
	done

	if [ -n "$(fpm_master_pid "$prefix")" ]; then
		info "重新啟動 PHP-FPM $tag 讓設定生效…"
		if ! restart_and_verify "$tag" "$prefix" "$cur"; then
			cp -p "$BACKUP_DIR/php$tag-php.ini-$RUN_ID.bak" "$ini"
			fpm_force_restart "$tag" "$prefix"
			fail_version "$tag" "重新啟動失敗，已還原 php.ini"
			return 1
		fi
		if [ -n "$PROBE_RESULT" ] && [ "${PROBE_RESULT##*|}" != 0 ]; then
			warn "PHP-FPM 回報 upload_progress 仍為開啟，可能被其他設定覆蓋，請手動檢查"
			set_result "$tag" vulnerable "$cur" "緩解設定未生效，仍有風險"
			return 0
		fi
	else
		info "PHP-FPM $tag 沒有在執行，設定將在下次啟動時生效"
	fi
	set_result "$tag" mitigated "$cur" "已套用緩解設定（仍建議改用 8.2 以上）"
}

# --------------------------------------------------------------- summary ----

print_summary() {
	local tag status color label sites any_vuln=0 failed=0
	title "處理結果"
	for tag in "${PLAN_TAGS[@]}"; do
		status=${RESULT_STATUS[$tag]:-}
		case "$status" in
			upgraded|patched|ok) color=$C_GREEN ;;
			mitigated) color=$C_YELLOW ;;
			*) color=$C_RED ;;
		esac
		case "$status" in
			upgraded)   label="✔ ${RESULT_NOTE[$tag]}" ;;
			patched)    label="✔ ${RESULT_NOTE[$tag]}" ;;
			ok)         label="✔ ${RESULT_NOTE[$tag]}" ;;
			mitigated)  label="! ${RESULT_NOTE[$tag]}" ;;
			fail)       label="✘ ${RESULT_NOTE[$tag]}"; failed=1 ;;
			*)          label="✘ ${RESULT_NOTE[$tag]}" ;;
		esac
		printf '  PHP %-3s  %-8s → %-8s  %s%s%s\n' "$tag" "${PLAN_CUR[$tag]}" \
			"${RESULT_AFTER[$tag]:-${PLAN_CUR[$tag]}}" "$color" "$label" "$C_RESET"
	done

	for tag in "${PLAN_TAGS[@]}"; do
		case "${RESULT_STATUS[$tag]:-}" in
			mitigated|vulnerable|warn) ;;
			*) continue ;;
		esac
		if [ "$any_vuln" = 0 ]; then
			printf '\n%s以下 PHP 版本官方已不再提供修補，請盡快在寶塔「網站 → 設定 → PHP 版本」改用 8.2 以上：%s\n' "$C_YELLOW" "$C_RESET"
			any_vuln=1
		fi
		sites=$(sites_using "$tag")
		printf '  PHP %-3s  使用中的網站：%s\n' "$tag" "${sites:-（沒有網站使用）}"
	done

	if [ "$MAIN_LOG" != /dev/null ]; then
		printf '\n'
		info "備份目錄：$BACKUP_DIR"
		info "執行記錄：$MAIN_LOG"
	fi
	return "$failed"
}

cleanup() {
	[ -n "$PROBE_DIR" ] && rm -rf "$PROBE_DIR"
	[ -n "$WORK_DIR" ] && [ -d "$WORK_DIR" ] && rm -rf "$WORK_DIR"
}

# Detaches from the tee pipe so the log is flushed before the shell prompt returns.
finish() {
	if [ "$MAIN_LOG" != /dev/null ]; then
		exec 1>&3 2>&3
		sleep 0.5
	fi
	exit "$1"
}

countdown() {
	local i
	[ "$ASSUME_YES" = 1 ] || [ "$IS_TTY" != 1 ] && return 0
	for i in 5 4 3 2 1; do
		progress "$(printf '%d 秒後開始，按 Ctrl+C 可取消…' "$i")"
		sleep 1
	done
	progress_done
}

main() {
	local tag action builds=0 need_patch=0 pending=0 rc=0
	[ -t 1 ] && IS_TTY=1
	exec 3>&1
	setup_colors
	parse_args "$@"
	preflight
	if [ "$CHECK_ONLY" != 1 ]; then
		setup_logging
		acquire_lock
	fi
	banner

	build_plan
	if [ ${#PLAN_TAGS[@]} -eq 0 ]; then
		warn "$PHP_ROOT 底下沒有找到任何已安裝的 PHP"
		finish 0
	fi
	print_plan

	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			upgrade) builds=$((builds + 1)) pending=1 ;;
			backport) builds=$((builds + 1)) pending=1 need_patch=1 ;;
			mitigate) pending=1 ;;
		esac
	done

	if [ "$CHECK_ONLY" = 1 ]; then
		printf '\n'
		if [ "$pending" = 1 ]; then
			info "以上為檢查結果，未做任何變更。移除 --check 參數即可開始處理"
			exit 2
		fi
		ok "所有可修補的 PHP 版本都已是安全版本"
		exit 0
	fi
	if [ "$pending" = 0 ]; then
		printf '\n'
		ok "沒有需要處理的版本"
		for tag in "${PLAN_TAGS[@]}"; do
			set_result "$tag" "${PLAN_ACTION[$tag]}" "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}"
		done
		print_summary
		finish 0
	fi

	trap cleanup EXIT
	mkdir -p "$WORK_DIR" || die "無法建立工作目錄 $WORK_DIR"
	setup_probe || die "無法建立測試檔案"
	if [ "$builds" -gt 0 ]; then
		ensure_build_tools "$need_patch"
		decide_jobs
		printf '\n'
		info "共 $builds 個版本需要重新編譯，每個約 5～20 分鐘；重新啟動 PHP 時網站會中斷 1～2 秒"
		if [ -z "${STY:-}" ] && [ -z "${TMUX:-}" ]; then
			info "提示：若是透過 SSH 執行，建議在 screen 或 tmux 中執行，以免連線中斷（中斷不會損壞現有 PHP）"
		fi
	fi
	countdown

	for tag in "${PLAN_TAGS[@]}"; do
		action=${PLAN_ACTION[$tag]}
		case "$action" in
			upgrade|backport) process_build "$tag" "$action" ;;
			mitigate) process_mitigation "$tag" ;;
			ok) set_result "$tag" ok "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			mitigated) set_result "$tag" mitigated "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			warn) set_result "$tag" warn "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			*) set_result "$tag" skip "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
		esac
	done

	print_summary || rc=1
	finish "$rc"
}

# ------------------------------------------------- embedded backport patches ----
# Source: https://github.com/php/php-src/commit/<BACKPORT_COMMIT>.patch (gzip + base64)

backport_blob_74() {
	cat <<'BLOB'
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
BLOB
}

backport_blob_80() {
	cat <<'BLOB'
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
BLOB
}

backport_blob_81() {
	cat <<'BLOB'
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
lr3hev0cFME1FaXYMHtX9KtYIv8fs3551YjCAAA=
BLOB
}

main "$@"
