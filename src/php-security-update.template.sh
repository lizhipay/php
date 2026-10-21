#!/usr/bin/env bash
#
# PHP security updater — CVE-2026-109618 / CVE-2026-109619 (unauthenticated RCE)
#
# Auto-detects every PHP install on the server (BaoTa/aaPanel, source builds under
# /usr/local or /opt, LiteSpeed lsphp, and php-fpm on PATH) and fixes each:
#   8.2 and newer    -> upgrade to the latest release of the same branch
#   7.4 / 8.0 / 8.1  -> last release + the PHP team's official backport patch
#   7.0-7.3, 5.4-5.6 -> last release + this project's port of that fix (unofficial)
#   older / unmatched -> official mitigation settings only
# Distro-packaged PHP is detected and left for the package manager (advice only).
#
# Advisory: https://www.php.net/archive/2026.php#2026-10-21-5
#
# Usage: bash php-security-update.sh [--check] [--only 74,82] [--jobs N] [-y]
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

# Branches with a newer fixed release on php.net → upgrade to it.
declare -A FIXED_RELEASE=([8.2]=8.2.35 [8.3]=8.3.36 [8.4]=8.4.27 [8.5]=8.5.12)

# SHA256 of the php.net source tarball for each pinned release (verified on download).
declare -A KNOWN_SHA256=(
	[8.5.12]=81a0f450349e84b08eb43faa85f8a4c835684f3cc1c50471775d1317a046c525
	[8.4.27]=5bafed9994c1a49796b25b5f61c22c9183bfe046b6acc7b363842d03c77f972f
	[8.3.36]=c93f3441f87f6ab156bef4432db215d7e61ca2c0183bb3a2aa28d9886ab59f53
	[8.2.35]=9db4204f0a2d1911277ae832185e07bb4c3b3559772753a70d2968ca346d6910
	[8.1.34]=3c5b060ec8e0d5dd1d8237823f3161cc8bc5342aab3c46893eba9857759c4bfa
	[8.0.30]=449d2048fcb20a314d8c218097c6d1047a9f1c5bb72aa54d5d3eba0a27a4c80c
	[7.4.33]=5a2337996f07c8a097e03d46263b5c98d2c8e355227756351421003bea8f463e
	[7.3.33]=9a369c32c6f52036b0a890f290327f148a1904ee66aa56e2c9a7546da6525ec8
	[7.2.34]=8b2777c741e83f188d3ca6d8e98ece7264acafee86787298fae57e05d0dddc78
	[7.1.33]=0055f368ffefe51d5a4483755bd17475e88e74302c08b727952831c5b2682ea2
	[7.0.33]=d71a6ecb6b13dc53fed7532a7f8f949c4044806f067502f8fb6f9facbb40452a
	[5.6.40]=56fb9878d12fdd921f6a0897e919f4e980d930160e154cbde2cc6d9206a27cac
	[5.5.38]=4f458c9b504269615715a62f182b7c2f89bb8284f484befc221b56a1571b506e
	[5.4.45]=25bc4723955f4e352935258002af14a14a9810b491a19400d76fcdfa9d04b28f
)

# EOL branches with no newer release: rebuild the last release + a source patch.
# 7.4/8.0/8.1 use the PHP security team's official backport; 7.0-7.3 and 5.4-5.6 use
# this project's port of that same fix (unofficial, see port-notes/ in the repo).
declare -A BACKPORT_BASE=(
	[8.1]=8.1.34 [8.0]=8.0.30 [7.4]=7.4.33
	[7.3]=7.3.33 [7.2]=7.2.34 [7.1]=7.1.33 [7.0]=7.0.33
	[5.6]=5.6.40 [5.5]=5.5.38 [5.4]=5.4.45
)
declare -A BACKPORT_OFFICIAL=([7.4]=1 [8.0]=1 [8.1]=1)
# Provenance note shown to the user / written to the patch marker.
declare -A BACKPORT_COMMIT=(
	[7.4]=712e60f9edfd03f0960fc4fc3c2c375f42b90aa2
	[8.0]=82f8f31b16a035c1b67cc253e79f7cc288f4cc20
	[8.1]=1d7dec178a094e6e75b229ce22754045f8c6070a
	[7.3]=lizhipay/php-backport [7.2]=lizhipay/php-backport
	[7.1]=lizhipay/php-backport [7.0]=lizhipay/php-backport
	[5.6]=lizhipay/php-backport [5.5]=lizhipay/php-backport [5.4]=lizhipay/php-backport
)
# SHA256 of each embedded patch, generated from patches/ at build time.
declare -A BACKPORT_SHA256
__BACKPORT_SHA256_ASSIGN__

# Opt-in session hardening patches (session.serialize_handler mismatch object
# injection — a separate issue from the two CVEs; see hardening/ in the repo).
readonly HARDEN_MARKER=".session-hardening"
declare -A HARDEN_SHA256
__HARDEN_SHA256_ASSIGN__

CHECK_ONLY=0
ASSUME_YES=0
HARDEN=0
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
declare -A PLAN_CUR PLAN_ACTION PLAN_TARGET PLAN_SHA PLAN_NOTE PLAN_HARDEN
declare -A RESULT_STATUS RESULT_AFTER RESULT_NOTE
declare -A RELEASE_CACHE
# Discovered PHP installs, keyed by a short id (tag). kind: baota|source|distro.
declare -A INSTALL_PREFIX INSTALL_KIND INSTALL_SERVICE INSTALL_LABEL
IS_BAOTA=0

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
	printf '  PHP 安全更新  v%s\n' "$SCRIPT_VERSION"
	printf '  修補 %s（PHP 遠端程式碼執行漏洞）\n' "$CVE_LABEL"
	printf '══════════════════════════════════════════════════════════\n'
	printf '%s' "$C_RESET"
	printf '%s  官方公告：%s%s\n' "$C_DIM" "$ADVISORY_URL" "$C_RESET"
}

usage() {
	cat <<EOF
PHP 安全更新腳本 v${SCRIPT_VERSION}
修補 ${CVE_LABEL}（PHP 遠端程式碼執行漏洞）
自動偵測伺服器上所有 PHP（寶塔/aaPanel、原始碼編譯、LiteSpeed、PATH 上的 php-fpm）

用法：bash php-security-update.sh [選項]

  --check        只檢查並列出處理計畫，不做任何變更
  --only 74,82   只處理指定的 PHP 版本（以逗號分隔，可用版本號如 74 或安裝代號）
  --jobs N       編譯並行數（預設依 CPU 與記憶體自動決定）
  --harden       額外套用 session 物件注入硬化（session.serialize_handler 混用，
                 與本次 CVE 無關的另一個問題）：重編打上硬化補丁並開啟 session.harden，
                 連已是最新版的 PHP 也會為此重編一次。會停用 session 物件反序列化，
                 可能影響把物件存進 session 的應用，請先用 --check --harden 確認。
  -y, --yes      不倒數，立即開始
  -h, --help     顯示本說明

處理方式：
  PHP 8.2 以上       升級到同系列最新版
  PHP 7.4/8.0/8.1    升級到該系列最後一版並套用 PHP 官方安全修補
  PHP 7.0-7.3/5.4-5.6 套用本專案移植的安全修補後重新編譯
  更舊 / 無法修補     套用官方緩解設定
  系統套件安裝的 PHP  只提示，改用套件管理工具更新（不自動重編）

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
			--harden) HARDEN=1 ;;
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
	if [ -s /var/bt_setupPath.conf ] && grep -q '^/[A-Za-z0-9._/-]\+$' /var/bt_setupPath.conf; then
		SETUP_PATH=$(head -n1 /var/bt_setupPath.conf | tr -d '[:space:]')
	fi
	SETUP_PATH=${SETUP_PATH:-/www}
	SETUP_PATH=${SETUP_PATH%/}
	if [ -d "$SETUP_PATH/server/panel" ] && [ -d "$SETUP_PATH/server/php" ]; then
		IS_BAOTA=1
		PHP_ROOT="$SETUP_PATH/server/php"
		WORK_DIR="$SETUP_PATH/server/php_security_update"
		BACKUP_DIR="$SETUP_PATH/backup/php_security_update"
	else
		WORK_DIR="/var/tmp/php-security-update"
		BACKUP_DIR="/var/backups/php-security-update"
	fi
	LOG_DIR="$BACKUP_DIR/logs"
	if command -v apt-get >/dev/null 2>&1; then
		PKG_MANAGER=apt-get
	elif command -v dnf >/dev/null 2>&1; then
		PKG_MANAGER=dnf
	elif command -v yum >/dev/null 2>&1; then
		PKG_MANAGER=yum
	fi
}

# True when the php binary at $1 is owned by the system package manager.
is_distro_owned() {
	local bin=$1 real
	real=$(readlink -f "$bin" 2>/dev/null || printf '%s' "$bin")
	case "$PKG_MANAGER" in
		apt-get) dpkg -S "$real" >/dev/null 2>&1 ;;
		dnf|yum) rpm -qf "$real" >/dev/null 2>&1 ;;
		*) return 1 ;;
	esac
}

# Finds a service manager handle for a running/known php-fpm of this install.
# Prints "init:<path>" | "systemd:<unit>" | "" (none).
detect_fpm_service() {
	local prefix=$1 tag=$2 unit frag
	if [ "$IS_BAOTA" = 1 ]; then
		[ -x "/etc/init.d/php-fpm-$tag" ] && { printf 'init:/etc/init.d/php-fpm-%s' "$tag"; return; }
		if command -v systemctl >/dev/null 2>&1 && systemctl cat "php-fpm-$tag.service" >/dev/null 2>&1; then
			printf 'systemd:php-fpm-%s.service' "$tag"; return
		fi
	fi
	if command -v systemctl >/dev/null 2>&1; then
		while read -r unit; do
			[ -n "$unit" ] || continue
			frag=$(systemctl show -p FragmentPath --value "$unit" 2>/dev/null)
			[ -n "$frag" ] && [ -f "$frag" ] || continue
			if grep -qF "$prefix/sbin/php-fpm" "$frag" 2>/dev/null || grep -qF "$prefix/" "$frag" 2>/dev/null; then
				printf 'systemd:%s' "$unit"; return
			fi
		done < <(systemctl list-units --type=service --all --no-legend --plain 2>/dev/null | awk '/php.*fpm|fpm.*php/ {print $1}')
	fi
	printf ''
}

# Adds one discovered install to the maps. $1=prefix $2=kind-hint ("" = autodetect).
register_install() {
	local prefix=$1 kind=$2 bin tag real
	prefix=${prefix%/}
	bin="$prefix/bin/php"
	[ -x "$bin" ] || return 1
	real=$(readlink -f "$bin" 2>/dev/null)
	for tag in "${!INSTALL_PREFIX[@]}"; do
		[ "$(readlink -f "${INSTALL_PREFIX[$tag]}/bin/php" 2>/dev/null)" = "$real" ] && return 1
	done
	if [ -z "$kind" ]; then
		if [ "$IS_BAOTA" = 1 ] && [ "${prefix#"$PHP_ROOT"/}" != "$prefix" ]; then
			kind=baota
		elif is_distro_owned "$bin"; then
			kind=distro
		else
			kind=source
		fi
	fi
	if [ "$kind" = baota ]; then
		tag=${prefix##*/}
	else
		tag=$(printf '%s' "${prefix#/}" | tr -c 'A-Za-z0-9' '_')
	fi
	INSTALL_PREFIX[$tag]=$prefix
	INSTALL_KIND[$tag]=$kind
	INSTALL_LABEL[$tag]=$([ "$kind" = baota ] && printf 'PHP %s' "$tag" || printf '%s' "$prefix")
	[ "$kind" = distro ] || INSTALL_SERVICE[$tag]=$(detect_fpm_service "$prefix" "$tag")
	PLAN_TAGS+=("$tag")
}

# Discovers every PHP install: BaoTa dirs, common source prefixes, and PATH php-fpm.
discover_installs() {
	local d p
	if [ "$IS_BAOTA" = 1 ]; then
		for d in "$PHP_ROOT"/[0-9][0-9]; do
			[ -d "$d" ] && register_install "$d" baota
		done
	fi
	for d in /usr/local/php /usr/local/php[0-9]* /usr/local/php/* \
		/opt/php /opt/php[0-9]* /opt/php/* /opt/remi/php*/root/usr \
		/usr/local/lsws/lsphp[0-9]* /www/server/php/*; do
		[ -d "$d" ] && [ -x "$d/bin/php" ] && register_install "$d"
	done
	for p in php php-fpm php-cgi; do
		d=$(command -v "$p" 2>/dev/null) || continue
		d=$(readlink -f "$d" 2>/dev/null)
		# <prefix>/bin/php or <prefix>/sbin/php-fpm
		d=${d%/bin/*}; d=${d%/sbin/*}
		[ -x "$d/bin/php" ] && register_install "$d"
	done
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
				libbz2-dev libgmp-dev libreadline-dev libc-ares-dev libzstd-dev libbrotli-dev
			;;
		dnf|yum)
			install_packages gcc gcc-c++ make pkgconfig patch libxml2-devel sqlite-devel \
				libcurl-devel oniguruma-devel openssl-devel zlib-devel libpng-devel \
				libjpeg-turbo-devel freetype-devel libwebp-devel libicu-devel libsodium-devel \
				libzip-devel libxslt-devel bzip2-devel gmp-devel readline-devel c-ares-devel \
				libzstd-devel brotli-devel
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

# Loaded php.ini path for an install (from `php --ini`), else the conventional path.
php_ini_path() {
	local prefix=$1 ini
	ini=$("$prefix/bin/php" -n -r 'echo php_ini_loaded_file() ?: "";' 2>/dev/null </dev/null)
	[ -z "$ini" ] && ini=$("$prefix/bin/php" -i 2>/dev/null </dev/null | sed -n 's/^Loaded Configuration File => //p' | head -n1)
	[ -n "$ini" ] && [ "$ini" != "(none)" ] || ini="$prefix/etc/php.ini"
	printf '%s' "$ini"
}

build_plan() {
	local dir tag cur branch target state fix_label vtag
	local -a tags=("${PLAN_TAGS[@]}")
	PLAN_TAGS=()
	for tag in "${tags[@]}"; do
		dir=${INSTALL_PREFIX[$tag]}
		cur=$(php_version_of "$dir")
		vtag=${cur%%.*}${cur#*.}; vtag=${vtag%%.*}
		if [ -n "$ONLY_TAGS" ] && [[ ",$ONLY_TAGS," != *",$tag,"* ]] && [[ ",$ONLY_TAGS," != *",$vtag,"* ]]; then
			continue
		fi
		PLAN_TAGS+=("$tag")
		PLAN_CUR[$tag]=${cur:-未知}
		if [ -z "$cur" ]; then
			PLAN_ACTION[$tag]=skip PLAN_NOTE[$tag]="無法取得版本，略過"
			continue
		fi
		branch=${cur%.*}

		if [ "${INSTALL_KIND[$tag]}" = distro ]; then
			if [ -n "${FIXED_RELEASE[$branch]:-}" ] || [ -n "${BACKPORT_BASE[$branch]:-}" ]; then
				PLAN_ACTION[$tag]=distro PLAN_NOTE[$tag]="系統套件安裝，請用套件管理工具更新（不自動重編）"
			else
				PLAN_ACTION[$tag]=distro PLAN_NOTE[$tag]="系統套件安裝且版本過舊，請用套件管理工具更新或改用新版"
			fi
		elif [ -n "${BACKPORT_BASE[$branch]:-}" ]; then
			target=${BACKPORT_BASE[$branch]}
			if [ -n "${BACKPORT_OFFICIAL[$branch]:-}" ]; then
				fix_label="官方安全修補"
			else
				fix_label="安全修補（本專案移植，非官方）"
			fi
			if [ "$cur" = "$target" ] && [ -f "$dir/$PATCH_MARKER" ]; then
				PLAN_ACTION[$tag]=ok PLAN_NOTE[$tag]="已套用${fix_label}"
			elif [ "$(ver_num "$cur")" -gt "$(ver_num "$target")" ]; then
				PLAN_ACTION[$tag]=skip PLAN_NOTE[$tag]="非官方版本號，無法判斷，請手動確認"
			else
				PLAN_ACTION[$tag]=backport PLAN_TARGET[$tag]=$target PLAN_SHA[$tag]=${KNOWN_SHA256[$target]}
				if [ "$cur" = "$target" ]; then
					PLAN_NOTE[$tag]="重新編譯並套用${fix_label}"
				else
					PLAN_NOTE[$tag]="升級到 $target 並套用${fix_label}"
				fi
			fi
		elif [ "$(ver_num "$cur")" -lt "$(ver_num 7.4.0)" ]; then
			state=$(upload_progress_state "$cur" "$(php_ini_path "$dir")")
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

# Second pass (only with --harden): schedule the session hardening patch for every
# rebuildable install — including ones already on the latest fixed release.
apply_harden_plan() {
	local tag branch cur
	for tag in "${PLAN_TAGS[@]}"; do
		cur=${PLAN_CUR[$tag]}
		[ "$cur" = 未知 ] && continue
		branch=${cur%.*}
		case "${INSTALL_KIND[$tag]}" in
			distro)
				# can't recompile; still offer the safe config subset + advice
				[ "${PLAN_ACTION[$tag]}" = distro ] && PLAN_NOTE[$tag]="${PLAN_NOTE[$tag]}；硬化只套用設定" ;;
			baota|source) ;;
			*) continue ;;
		esac
		[ -n "${HARDEN_SHA256[$branch]:-}" ] || { PLAN_NOTE[$tag]="${PLAN_NOTE[$tag]}（PHP $branch 無硬化補丁）"; continue; }
		case "${PLAN_ACTION[$tag]}" in
			backport|upgrade)
				PLAN_HARDEN[$tag]=1 PLAN_NOTE[$tag]="${PLAN_NOTE[$tag]} + session 硬化" ;;
			ok)
				if [ -f "${INSTALL_PREFIX[$tag]}/$HARDEN_MARKER" ]; then
					PLAN_NOTE[$tag]="已修補且已硬化"
				elif [ -n "${KNOWN_SHA256[$cur]:-}" ]; then
					PLAN_ACTION[$tag]=harden PLAN_TARGET[$tag]=$cur PLAN_SHA[$tag]=${KNOWN_SHA256[$cur]} PLAN_HARDEN[$tag]=1
					PLAN_NOTE[$tag]="重新編譯以套用 session 硬化"
				else
					PLAN_NOTE[$tag]="${PLAN_NOTE[$tag]}（版本 $cur 無法下載原始碼，硬化請手動處理）"
				fi ;;
		esac
	done
}

print_plan() {
	local tag color
	title "已安裝的 PHP 版本"
	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			ok) color=$C_GREEN ;;
			upgrade|backport|mitigate|distro|harden) color=$C_YELLOW ;;
			*) color=$C_RED ;;
		esac
		printf '  %-20s %-8s  %s%s%s\n' "${INSTALL_LABEL[$tag]}" "${PLAN_CUR[$tag]}" "$color" "${PLAN_NOTE[$tag]}" "$C_RESET"
	done
}

sites_using() {
	local tag=$1 f list=()
	[ "$IS_BAOTA" = 1 ] || return 0
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

# Runs an action on the install's php-fpm via its detected service handle.
# Returns 127 when the install has no managed service. fd 3/9 closed so the
# daemon does not inherit the terminal or the lock.
fpm_service() {
	local svc=${INSTALL_SERVICE[$1]:-}
	case "$svc" in
		init:*) "${svc#init:}" "$2" 3>&- 9>&- ;;
		systemd:*) systemctl "$2" "${svc#systemd:}" 3>&- 9>&- ;;
		*) return 127 ;;
	esac
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

# Returns 0 = restarted+verified, 1 = failed, 3 = binary swapped but FPM needs a
# manual restart (no service manager and graceful reload could not be confirmed).
restart_and_verify() {
	local tag=$1 prefix=$2 expect=$3 pid
	if [ -n "${INSTALL_SERVICE[$tag]:-}" ]; then
		fpm_service "$tag" restart </dev/null >>"$CUR_LOG" 2>&1
		verify_fpm "$tag" "$prefix" "$expect" && return 0
		warn "改用強制重啟再試一次…"
		fpm_force_restart "$tag" "$prefix"
		verify_fpm "$tag" "$prefix" "$expect" && return 0
		return 1
	fi
	# No service manager: graceful reload re-execs the master with the new binary.
	pid=$(fpm_master_pid "$prefix")
	if [ -n "$pid" ]; then
		info "以 SIGUSR2 平滑重載 PHP-FPM（無服務管理器）…"
		kill -USR2 "$pid" 2>/dev/null
		sleep 2
		verify_fpm "$tag" "$prefix" "$expect" && return 0
		warn "無法自動重載這個 PHP-FPM，新版程式已就位，請手動重啟它讓修補生效"
		return 3
	fi
	return 3
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
	backport_blob "$branch" | base64 -d | gzip -dc >"$pf" 2>>"$CUR_LOG"
	if [ ! -s "$pf" ] || [ "$(sha256_of "$pf")" != "${BACKPORT_SHA256[$branch]:-}" ]; then
		err "內建修補檔校驗失敗，腳本可能已損毀，請重新下載"
		return 1
	fi
	if ! patch -p1 -d "$dir" --forward --batch <"$pf" >>"$CUR_LOG" 2>&1; then
		err "修補檔套用失敗"
		return 1
	fi
	if [ -n "${BACKPORT_OFFICIAL[$branch]:-}" ]; then
		ok "已套用 PHP 官方安全修補（commit ${BACKPORT_COMMIT[$branch]:0:12}）"
	else
		ok "已套用本專案移植的安全修補（PHP $branch，非官方）"
	fi
}

apply_hardening() {
	local branch=$1 dir=$2 pf="$WORK_DIR/php-$1-hardening.patch"
	harden_blob "$branch" | base64 -d | gzip -dc >"$pf" 2>>"$CUR_LOG"
	if [ ! -s "$pf" ] || [ "$(sha256_of "$pf")" != "${HARDEN_SHA256[$branch]:-}" ]; then
		err "內建 session 硬化補丁校驗失敗"
		return 1
	fi
	if ! patch -p1 -d "$dir" --forward --batch <"$pf" >>"$CUR_LOG" 2>&1; then
		err "session 硬化補丁套用失敗"
		return 1
	fi
	ok "已套用 session 物件注入硬化補丁（PHP $branch）"
}

# Writes the opt-in session hardening + safe config into an install's php.ini.
# want_flag=1 adds session.harden=1 (only for binaries built with the patch).
apply_harden_config() {
	local ini=$1 want_flag=$2
	[ -f "$ini" ] || return 0
	cp -p "$ini" "$BACKUP_DIR/$(basename "$ini").$RUN_ID.bak" 2>/dev/null
	set_ini_value "$ini" session.upload_progress.enabled Off
	set_ini_value "$ini" session.use_strict_mode 1
	set_ini_value "$ini" session.use_only_cookies 1
	[ "$want_flag" = 1 ] && set_ini_value "$ini" session.harden 1
	return 0
}

# Idempotently sets "key = value" in a php.ini (updates existing, else appends).
set_ini_value() {
	local ini=$1 key=$2 val=$3 esc
	esc=$(printf '%s' "$key" | sed 's/[.[\*^$]/\\&/g')
	if grep -qE "^[[:space:]]*;?[[:space:]]*${esc}[[:space:]]*=" "$ini"; then
		sed -i -E "s|^[[:space:]]*;?[[:space:]]*${esc}[[:space:]]*=.*$|${key} = ${val}|" "$ini"
	else
		printf '\n%s = %s\n' "$key" "$val" >>"$ini"
	fi
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

# When the link step fails with "cannot find -l<name>" (common on CentOS where the
# runtime lib<name>.so.N exists but the dev symlink lib<name>.so is missing, e.g.
# zstd pulled in via BaoTa's curl), install the -devel package and/or create the
# missing dev symlink next to the runtime library. Returns 0 if anything was fixed.
resolve_missing_libs() {
	local log=$1 names name real base fixed=0
	names=$(grep -oE 'cannot find -l[A-Za-z0-9_.+-]+' "$log" 2>/dev/null | sed 's/cannot find -l//' | sort -u)
	[ -n "$names" ] || return 1
	for name in $names; do
		install_packages "lib${name}-dev" "${name}-devel" "lib${name}-devel" >/dev/null 2>&1
		if printf 'int main(void){return 0;}' | "${CC:-cc}" -x c - "-l${name}" -o /dev/null >/dev/null 2>&1; then
			fixed=1; continue
		fi
		real=$(ldconfig -p 2>/dev/null | awk -v n="lib${name}.so." 'index($1,n)==1 {print $NF; exit}')
		[ -n "$real" ] && [ -e "$real" ] || real=$(find /lib /lib64 /usr/lib /usr/lib64 /usr/local -maxdepth 5 -name "lib${name}.so.*" 2>/dev/null | head -n1)
		if [ -n "$real" ] && [ -e "$real" ]; then
			base="lib${name}.so"
			if ln -sf "$real" "$(dirname "$real")/$base" 2>/dev/null; then
				ldconfig 2>/dev/null
				warn "已建立缺少的連結符號連結：$(dirname "$real")/$base → $real"
				fixed=1
			fi
		else
			err "連結需要 lib${name}，但系統找不到，請先安裝 lib${name} 的開發套件後重試"
		fi
	done
	[ "$fixed" = 1 ]
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
	local tag=$1 cur=$2 rc prefix pdir pbase
	prefix=${INSTALL_PREFIX[$tag]}
	pdir=$(dirname "$prefix"); pbase=$(basename "$prefix")
	BACKUP_FILE="$BACKUP_DIR/php$tag-$cur-$RUN_ID.tar.gz"
	info "備份目前的 PHP $tag → $BACKUP_FILE"
	tar -czf "$BACKUP_FILE" -C "$pdir" --exclude="$pbase/src" --exclude="$pbase/src.tar.gz" \
		--exclude="$pbase/var/log/*" --exclude="$pbase/var/run/*" "$pbase" 2>>"$CUR_LOG"
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
	if ! tar -xzf "$BACKUP_FILE" -C "$(dirname "$prefix")" 2>>"$CUR_LOG"; then
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
		restart_and_verify "$tag" "$prefix" "$target"; rc=$?
	else
		info "PHP-FPM $tag 原本沒有在執行，維持停止狀態"
	fi
	if [ "$rc" != 1 ]; then
		cli=$("$prefix/bin/php" -n -r 'echo PHP_VERSION;' 2>/dev/null </dev/null)
		if [ "$cli" != "$target" ]; then
			err "命令列 PHP 版本為 ${cli:-無法執行}，預期為 $target"
			rc=1
		fi
	fi
	[ "$rc" = 1 ] && restore_backup "$tag" "$prefix" "$was_running"
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
	elif [ "$mode" != harden ]; then
		rm -f "$prefix/$PATCH_MARKER"
	fi
	if [ -n "${PLAN_HARDEN[$tag]:-}" ]; then
		printf 'session_hardening=session.serialize_handler-mismatch\nbase=%s\ndate=%s\n' \
			"$target" "$(date '+%F %T')" >"$prefix/$HARDEN_MARKER"
	fi
	[ -f "$prefix/src.tar.gz" ] && cp -f "$tarball" "$prefix/src.tar.gz"
}

process_build() {
	local tag=$1 mode=$2
	local prefix="${INSTALL_PREFIX[$1]}" cur=${PLAN_CUR[$1]} target=${PLAN_TARGET[$1]} sha=${PLAN_SHA[$1]}
	local build="$WORK_DIR/build-$tag" stage="$WORK_DIR/stage-$tag"
	local tarball="$WORK_DIR/php-$target.tar.gz" label=$target staged built free
	CUR_LOG="$LOG_DIR/php$tag-build-$RUN_ID.log"
	[ "$mode" = backport ] && label="$target + 安全修補"
	[ "$mode" = harden ] && label="$target（重編以套用 session 硬化）"
	[ -n "${PLAN_HARDEN[$tag]:-}" ] && [ "$mode" != harden ] && label="$label + session 硬化"
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
	if [ -n "${PLAN_HARDEN[$tag]:-}" ] && ! apply_hardening "${target%.*}" "$build"; then
		fail_version "$tag" "session 硬化補丁套用失敗"
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
		if resolve_missing_libs "$CUR_LOG"; then
			info "已補上缺少的連結函式庫，重試編譯…"
			run_make "$build" || { show_log_tail "$CUR_LOG"; fail_version "$tag" "編譯失敗（線上版本沒有任何變動）"; return 1; }
		else
			show_log_tail "$CUR_LOG"
			fail_version "$tag" "編譯失敗（線上版本沒有任何變動）"
			return 1
		fi
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

	# Enable hardening in php.ini before the restart so reloaded workers pick it up
	# (make install does not touch php.ini; the backup above covers rollback).
	[ -n "${PLAN_HARDEN[$tag]:-}" ] && apply_harden_config "$(php_ini_path "$prefix")" 1
	swap_install "$tag" "$prefix" "$staged" "$target"; local swap_rc=$?
	if [ "$swap_rc" = 1 ]; then
		fail_version "$tag" "新版本啟動驗證失敗，已自動還原為 $cur"
		return 1
	fi
	finalize_install "$tag" "$prefix" "$target" "$mode" "$tarball"
	rm -rf "$build" "$stage" "$tarball"
	local manual="" hsfx=""
	[ "$swap_rc" = 3 ] && manual="（請手動重啟 PHP-FPM 讓修補生效）"
	[ -n "${PLAN_HARDEN[$tag]:-}" ] && hsfx="＋session 硬化"
	if [ "$mode" = harden ]; then
		ok "PHP $tag 已重新編譯並套用 session 硬化$manual"
		set_result "$tag" patched "$target" "已套用 session 硬化$manual"
	elif [ "$mode" = backport ]; then
		if [ -n "${BACKPORT_OFFICIAL[${target%.*}]:-}" ]; then
			ok "PHP $tag 已更新為 $target 並套用官方安全修補$hsfx$manual"
			set_result "$tag" patched "$target" "已套用官方安全修補$hsfx$manual"
		else
			ok "PHP $tag 已重新編譯並套用安全修補（本專案移植，非官方）$hsfx$manual"
			set_result "$tag" patched "$target" "已套用安全修補（本專案移植）$hsfx$manual"
		fi
	else
		ok "PHP $tag 已升級為 $target$hsfx$manual"
		set_result "$tag" upgraded "$target" "已升級$hsfx$manual"
	fi
}

process_mitigation() {
	local tag=$1 prefix="${INSTALL_PREFIX[$1]}" cur=${PLAN_CUR[$1]} f
	local ini; ini=$(php_ini_path "$prefix")
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
	local tag status color label sites any_vuln=0 any_distro=0 failed=0
	title "處理結果"
	for tag in "${PLAN_TAGS[@]}"; do
		status=${RESULT_STATUS[$tag]:-}
		case "$status" in
			upgraded|patched|ok) color=$C_GREEN ;;
			mitigated|distro) color=$C_YELLOW ;;
			*) color=$C_RED ;;
		esac
		case "$status" in
			upgraded|patched|ok) label="✔ ${RESULT_NOTE[$tag]}" ;;
			mitigated|distro)    label="! ${RESULT_NOTE[$tag]}" ;;
			fail)                label="✘ ${RESULT_NOTE[$tag]}"; failed=1 ;;
			*)                   label="✘ ${RESULT_NOTE[$tag]}" ;;
		esac
		printf '  %-20s %-8s → %-8s  %s%s%s\n' "${INSTALL_LABEL[$tag]}" "${PLAN_CUR[$tag]}" \
			"${RESULT_AFTER[$tag]:-${PLAN_CUR[$tag]}}" "$color" "$label" "$C_RESET"
	done

	for tag in "${PLAN_TAGS[@]}"; do
		[ "${RESULT_STATUS[$tag]:-}" = distro ] || continue
		if [ "$any_distro" = 0 ]; then
			printf '\n%s以下 PHP 由系統套件安裝，請用套件管理工具更新（發行版已提供修補）：%s\n' "$C_YELLOW" "$C_RESET"
			any_distro=1
			case "$PKG_MANAGER" in
				apt-get) printf '  指令範例：apt-get update && apt-get install --only-upgrade "php*" && systemctl restart "php*-fpm"\n' ;;
				dnf|yum) printf '  指令範例：%s -y update "php*" && systemctl restart "php*-fpm"\n' "$PKG_MANAGER" ;;
			esac
		fi
		printf '  %s（PHP %s）\n' "${INSTALL_LABEL[$tag]}" "${PLAN_CUR[$tag]}"
	done

	for tag in "${PLAN_TAGS[@]}"; do
		case "${RESULT_STATUS[$tag]:-}" in
			mitigated|vulnerable|warn) ;;
			*) continue ;;
		esac
		if [ "$any_vuln" = 0 ]; then
			printf '\n%s以下 PHP 版本官方已不再提供修補，建議盡快改用 8.2 以上：%s\n' "$C_YELLOW" "$C_RESET"
			any_vuln=1
		fi
		sites=$(sites_using "$tag")
		printf '  %-20s%s\n' "${INSTALL_LABEL[$tag]}" "${sites:+  使用中的網站：$sites}"
	done

	if [ "$HARDEN" = 1 ]; then
		printf '\n%sSession 硬化提醒：%s\n' "$C_YELLOW" "$C_RESET"
		printf '  • 已開啟 session.harden（停用 session 物件反序列化）。若有應用把物件存進 session 會受影響，請測試。\n'
		printf '  • 請一併移除各網站 .user.ini / .htaccess / FPM pool 中對 session.serialize_handler 的覆寫，全站統一為 php_serialize。\n'
		printf '  • 登入後呼叫 session_regenerate_id(true) 屬應用層，請自行在程式碼落實。\n'
	fi

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

	discover_installs
	if [ ${#PLAN_TAGS[@]} -eq 0 ]; then
		warn "這台伺服器上沒有找到任何已安裝的 PHP"
		finish 0
	fi
	build_plan
	if [ ${#PLAN_TAGS[@]} -eq 0 ]; then
		warn "沒有符合 --only 條件的 PHP"
		finish 0
	fi
	[ "$HARDEN" = 1 ] && apply_harden_plan
	print_plan

	local advise=0
	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			upgrade) builds=$((builds + 1)) pending=1 ;;
			backport) builds=$((builds + 1)) pending=1 need_patch=1 ;;
			harden) builds=$((builds + 1)) pending=1 need_patch=1 ;;
			mitigate) pending=1 ;;
			distro|warn) advise=1 ;;
		esac
		[ -n "${PLAN_HARDEN[$tag]:-}" ] && need_patch=1
	done

	if [ "$CHECK_ONLY" = 1 ]; then
		printf '\n'
		if [ "$pending" = 1 ]; then
			info "以上為檢查結果，未做任何變更。移除 --check 參數即可開始處理"
			exit 2
		fi
		if [ "$advise" = 1 ]; then
			warn "沒有需要本腳本重編的版本，但有 PHP 需你另外處理（見上方標示），例如系統套件更新"
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
			upgrade|backport|harden) process_build "$tag" "$action" ;;
			mitigate) process_mitigation "$tag" ;;
			ok) set_result "$tag" ok "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			mitigated) set_result "$tag" mitigated "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			distro)
				[ "$HARDEN" = 1 ] && apply_harden_config "$(php_ini_path "${INSTALL_PREFIX[$tag]}")" 0
				set_result "$tag" distro "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			warn) set_result "$tag" warn "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			*) set_result "$tag" skip "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
		esac
	done

	print_summary || rc=1
	finish "$rc"
}

# ------------------------------------------------- embedded backport patches ----
# Each patch (patches/php-<branch>.patch) is gzip+base64-embedded below at build time.
# backport_blob <branch> writes the encoded blob to stdout.
__BACKPORT_BLOBS__

# Opt-in session hardening patches (hardening/php-<branch>-session-hardening.patch).
__HARDEN_BLOBS__

main "$@"
