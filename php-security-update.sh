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
BACKPORT_SHA256[5.4]=81523508b66f063d47205801c244452b72b619848b89dbf1cd223837e55d6b24
BACKPORT_SHA256[5.5]=fc5bc95ed86fc53205cb3f247e40a2aac57940865db1a4331a72644f8e90e2f8
BACKPORT_SHA256[5.6]=c73347869d043b7749bf1ef017486819c867c0a6dc4762271cf851cce0dbcb00
BACKPORT_SHA256[7.0]=24cb0884dcb471f803510a98a7254be913ca90d62caf73297fc12a960ec96303
BACKPORT_SHA256[7.1]=b346f7596c77d8397409b96d6dbba564c1ab9b78a876e2a52b2fdb0a05a4e6f8
BACKPORT_SHA256[7.2]=b69c1bf7a23adaed7a04c980a7c2ffe523674b9da19756605293d40d5f99b4c7
BACKPORT_SHA256[7.3]=5bd1fc374e35b10193e57d8113486993ebf3294aeb6aeea2076a2cabb1ad2a2e
BACKPORT_SHA256[7.4]=5fe57ca6ee96d59b36c6e0ca842843c50884f177bef1e85234cf669b577f5e48
BACKPORT_SHA256[8.0]=534478c973cef6f493605b7af907f639a364912ee92c24598ddae44c3bc72d1c
BACKPORT_SHA256[8.1]=c85ad0fddcbff7f2318617eeaa54d271135463b5bf70a01228447e3ed78de96e

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

print_plan() {
	local tag color
	title "已安裝的 PHP 版本"
	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			ok) color=$C_GREEN ;;
			upgrade|backport|mitigate|distro) color=$C_YELLOW ;;
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
	else
		rm -f "$prefix/$PATCH_MARKER"
	fi
	[ -f "$prefix/src.tar.gz" ] && cp -f "$tarball" "$prefix/src.tar.gz"
}

process_build() {
	local tag=$1 mode=$2
	local prefix="${INSTALL_PREFIX[$1]}" cur=${PLAN_CUR[$1]} target=${PLAN_TARGET[$1]} sha=${PLAN_SHA[$1]}
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

	swap_install "$tag" "$prefix" "$staged" "$target"; local swap_rc=$?
	if [ "$swap_rc" = 1 ]; then
		fail_version "$tag" "新版本啟動驗證失敗，已自動還原為 $cur"
		return 1
	fi
	finalize_install "$tag" "$prefix" "$target" "$mode" "$tarball"
	rm -rf "$build" "$stage" "$tarball"
	local manual=""
	[ "$swap_rc" = 3 ] && manual="（請手動重啟 PHP-FPM 讓修補生效）"
	if [ "$mode" = backport ]; then
		if [ -n "${BACKPORT_OFFICIAL[${target%.*}]:-}" ]; then
			ok "PHP $tag 已更新為 $target 並套用官方安全修補$manual"
			set_result "$tag" patched "$target" "已套用官方安全修補$manual"
		else
			ok "PHP $tag 已重新編譯並套用安全修補（本專案移植，非官方）$manual"
			set_result "$tag" patched "$target" "已套用安全修補（本專案移植）$manual"
		fi
	else
		ok "PHP $tag 已升級為 $target$manual"
		set_result "$tag" upgraded "$target" "已升級$manual"
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
	print_plan

	local advise=0
	for tag in "${PLAN_TAGS[@]}"; do
		case "${PLAN_ACTION[$tag]}" in
			upgrade) builds=$((builds + 1)) pending=1 ;;
			backport) builds=$((builds + 1)) pending=1 need_patch=1 ;;
			mitigate) pending=1 ;;
			distro|warn) advise=1 ;;
		esac
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
			upgrade|backport) process_build "$tag" "$action" ;;
			mitigate) process_mitigation "$tag" ;;
			ok) set_result "$tag" ok "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			mitigated) set_result "$tag" mitigated "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
			distro) set_result "$tag" distro "${PLAN_CUR[$tag]}" "${PLAN_NOTE[$tag]}" ;;
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
backport_blob() {
	case "$1" in
	5.4) cat <<'BLOB'
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
AA==
BLOB
		;;
	5.5) cat <<'BLOB'
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
BLOB
		;;
	5.6) cat <<'BLOB'
H4sIAAAAAAAC/+07aXPbRrKfxV8x5ivH4CmC4inFztISJbMiUXoS5Ti72UINgQGJFQhgceiIo//+
uucAAQqU5STO+xJWIhKNnp6evntm/J6aN4EfxsS3SXl06zsWiWIaM2L6YZgEseN75NahZE4d10/i
Mol9cvHhgnSbvWanRbTx+WmdeD4Mtx3ToS4gCoKVZql07NyTkw9Xo8bdYHnXuBva943/9Id3RDv8
OG60W+1eQ28Ne/qgQhoNcn5+tktd1zcb/i0Lbde/I67vLf6zCp5wtCbcu1vZjU54220Ee2GwSXjI
CcNol5GQ/TdhUdzw7zxmkYXrz4FZQThkScRKpevp+fHx5HAyOiXUo66/eEgX01RrJoAZkXjJyPnp
Efkn8yzCvIXjMaL5rkV+BYCxWhG+Dhr7Yb2E4A80Ws7oHLi4c+IleZ+YNywm1SoNxc+Ii5APjuLQ
8RZ1Mru6PDu9MqowV8ioRVbUDP2oUieRDyAnKjkRmZ7PCCWWEzIzJjQIXAfmRIWBLpHFVCf9ZgfQ
bJtoSQATMLoCYa5WTlzq623Wa9lDZtlWa88GobVss2Obe2bb3Ot37U57PmxR2q4ccIoWs5kXObeM
OF7MvJgAF44FP2Bmt85RTN+Ct1GJWjSIQdJgL93mPWA5/ipqKgkZEbWZwcLQDw12r1WQELtHUcOQ
f46nR8boYiLWyriYd5V0Yt9qmqX3XMIwDqyGRA5aB/VA7DBijgoVQgFaIANOQ5lSQEEBWkBDJ34Q
2sC3XRBQ5MxdED3Y7RVjBFlpeH7Mot1ur7myiO2HhIFhPoAqgoBZu3KBu9PGiAADoHQwBpBt5HsR
2P4I9PFA7NBf8RmC0IlitJNgGTSk84AmgFffjzkj+yUCH+DPXJJGoIPlwpR3NLTg15xDv08Hc6xS
ieu00Vg4oP7dtZS4bJommT+FlRzPYvfE7M/pnOntZnPQG3StfrdL9Far1+mUGuAwBbRKtVqtkN4/
/kEaQ73eJzX+Fx7RpxyT8FCitB1QzzE1EyQTE3NJQ1JdsSiiC1Ypkf9xbKHxo/H76xPy3XdoZSAp
S/sw+jg2fpycnlaeQE/Gs4vJEYzeuXFcV1uwOHAsDdzjanJyNT75WDkAwjC5Y5caO+zeiTUdQLUd
I/1NHkukRHarTz+7fFF6v9Oq90iNf3eGuLLULnNri5ZJbEFU0RRgyWhAqvi3jm5C7MR1UywBihwX
nAa4fxR81FAImlwh0QzjZHp9aBh83eqBvCNtwiGvlCgMYzKdjU+Nw/Ozi8np+DL/9mh0+dNkujli
GST3G7DR5FOlVNuyupyfZjUI1rmicZ00m80KMEljiFzzJGbAqaZ5fsjiJPQqKHWpiFqptlslX84x
T9PDProPiA0dyaYQzks1UlVBFkdzBrkDCgVDPFmtIAjAJOCEDjCNMRTCYph4Hjg5p+ThAgSpsTG+
vDy/JEsg4TJBSUaMBqIL3Ur+KgSZBGJUJRVyt/QhgyClFVv5PEY8YCDyPZgegk0MUZgz4uAv51dm
NQnY2R+Sean2GQw6+1YMsdG26IqhuScoNQGG2MY8H4G3FB5gEA0XET7LVHM8nh1+0FBfAENz5Ow4
kQGpInAwNGoS87BSITj3Tn5C8lasAJxRjmFW+nI99mA9UvBUOE68yo96JMyNILkAb+MTzfFAOsxM
0AC2MgR41IwhYRl+YNAwpA8V8kMRtPEuHbVPptenp0Vswjg/wCcjiEMkpFXzICAjkfdJK8NyMXPb
phEjpRZe5YdtW2j52rvxIL6U5Vj4a3OnsbUotgC9Tsq/eMfoPMIg9km5Iq0BnDGMNTSHOhEWJt5s
ElDWh5hqLChOS5+fzAgWT15H4AYEF0deW7945TrJM1/PGaiwP4gTmISXcRzs7+5GScCLsJWDNZBv
x00wk92b+a4+bO11de5JEEAhnmGZZkDQ22sjN7abREvJTD4OZfJADYVVmLTWblgU2iF4F3gmQCNw
byOGBUN9VZeppLtXhxQLuWTYq+vdbVnyixPuGApuQ+lggKw1kWbwb+NdyCIWQm3Go8oxJATjdDId
G4eHm5Dx2cXsZ4BjGtzZyQ9WZom5qcEtULxPi/K3YKBohY2dZ4MPvC6IPgDdDDcAekG0AazfG27W
Q78q3sCwLwScQp4KYssPz8abfSHvAi7zseWHrcFmv5XldgtfW2eRg5UeCuJNIb1MwFHDNw2F6Pwd
F3YMSVFQ4o+CnKoSNJl/6xxhR/kSf5B+1MiXiRJRhRCFiktCXFX5wQfdUWmTT23yWlrwUmzebbXo
F4XQIkQBzC9ErQTDT5GkEF5cAai4KwmQIlFsyqJYGBlp7PxJ0RpJgfa/OmI3nkRspPQkZmcXVluv
al3cK7VKIxMRJesKT2Td5hjwf7ao08RkUj6iOZAxOhdz51Bz3pBqqihGQ3NpuJAC5bvCNkDmhDhM
mMGn4Hmh3em3sXOC726ud3I8rgA5ihsDtSyI0JEmYR7UmfOULn6lD9DxRizG1oiITzlclTUJxbXB
G7T76+n408X4cDY+0pRwVFR7zkVJ+cKPsFcWewALqJZT2YL9yPo3U5trr39NoDDGvzX8WwGbyrBf
Vwxz+Rc7wLebEtKfWB+GQd6OqWeQ9oHQUrfF+1v47nwDLYEpJx46wumFcXV9fFwi6vOsksjG5/9L
ZYV8/JUK3Pxk1Kk+j6XNtxnltoULdtvfwgU3PmW9rLWkD/6t5b9Syx2p5c5foeVwI9z+req/UtXd
rlB1d/AtcioXR4J7Q70Ozgr1hJaFVTgVWGoeinRg5XmgoFqYkZHyuw301v2x/Jz+najXiVqqr5K1
gX5L2EB/71vYgOUnuETDYm5M0QAEoIJKawC4UKOaYcEa5ZgKefUWfv+txsJ6ayCD9UAG6/wuaVUy
u+IMyAOzF+sPiZVA6uk+DYznJTnoMWcQ2/jfUGs6/B2ZTGfG2ejTy5R6xdnOClGJuE5W9J7Pi4di
ry2QpaL8nMp+J8GcDpRMQ+amCxPd0LMnTcuCk6GlPGnq60N7aHbNZrM36M47e9be8ydNyy0nTUux
k9bT+ZkMfA3QMtbbZxabJwuBa0A7F0BH93TLHJayPlsU6hfS5BZtJHgipeGmVcioKx7VQezR4ZdG
B4zevIDEH9v0x20CguPHn2bjy6lxqFXEMRaxKQ6gJh6R+CH59Za6byJstLeozsUzgI1DQgmTqtuz
usM+3es3m9056ww7rcE21alxm6pTcK46vctVB1+DLYdpHB00CabnP2hrEKm6GHZ3zCQM8dD5LfHY
fSxtF1zCbbxb4vlOZksdQDE09iSznQkg00/48Jbs8LeIRp0y59aSHj0L4bB+x7RbbN5stoZtS7fa
9jbhpAM3pZO+QPF0hjxlia91xnrvLNCYqkQeeOPDDRdGeIuZR72vnI1OT88PeRj0bQmuYMVx39Ar
VQk+hUKiIqIw3+oLbys8FO7sGLMPl+PRkXFxOfk4mo2Ns+vZ+JNxPQWaP2pW7FNjlcTsXu73rENb
JqKlR/I2xR1VPPiXwYjJlCEOHLZGsJcRIDs8YsH6G+9uQAQ3B+oJotydhQXZ/UFes2AsuxHEdAiK
6psrtxAu9TtvW632Xk9vNq1ha97tUj2v3+KxQsXF73hu6/WGPLeJ72xlEuPhviHRjdA29UGvb5gg
AbyEoiVe5CzwcJjvqd+CG9RlOuQPhkVjihCZoYpo+aGzSAlKxUPgh0ABMvviAE1Omp0OFhpSFd7k
cYI6NXh1caUpQszDyy+WPKXb9pb89hvR13yJogDZU56eU+qKOt7uFQQQrsrMk1RgZ2gDfXPYbNIe
+Olc30g82RFCbVkIKqvbHtT1Aanhd3sPlYUv1zErooED0Yrv7IONqrMDfivhUerh6kSTZ8SG49l+
pUmTeAlpgYVyoQx3FZ9D4y6z/X3uvOa5OQMaRXd+aL1g3hT1mbkVzovnt5wFQF4wu0R8Zm6B8ZKZ
IY3iNSUjfgiYYSXB89M/wS7mYRPtRYyI1PUCzecwtzCQQSmYnNvlyrcSlzXX5ilnLX6ZPfd66mX4
Z+1l4kl6GYXQOO/OB82mTtmg3+q0CrxMjsh4mYSgl/XAu6AuwC8eEPE8YDKdGO/HJ5MpVjc7CjKe
zi5/1sqWE2G8MOzEM7HOjcp1yCll/lehXv18NRufAQRl8wwN0wUzZr+HAiQbfiZiJIHrU0uSaLcK
iPymHi/Gl0eTy5RmrYjmKnFjB2+MGHPfgqISfiHtckP/CsrYfl7NIJsrWZ6fn45HU62M+fTOSELX
sP2AeUiyzAk/Wfa5dx1AkGfvfd+Fx42BAMGEYUJfY4irlFEdj4PXj5Uvs+B4pptYDFfX+joe5MiX
cMFLz8FAXOUaDPT6MO0bcKxyrPQSl8ipVrJaPfAyC2tpzXnbOiDO99PrM2N2OTr80fg4urwCSK2m
6if0u4sTDY+/0rn/5fxbvd7BchwPbQ2opULtuyJUURvtQCl/Ji4PUdOEhAwpny7AXQACvLA813hx
Iwm0ygExXQa9QrxkggpUjBb1FniOTgIfu/gQb1PS/GVYdQ3WpJ7nx+LmJAQVeTkJ6RQwmok4shTD
P09P4bjkh3t9Lvlh5yslL08H+WW/IxT6GCYRP4zL8f9ej69mxtWH69nR+U9T7Wp0PObXG6ajs/HT
kIp3PoEr6kUuWJOFtwSfH6CektABZNlIVl44aMXipW9V1jcQsTvLrIPLFqT7uxQtFANaESE8MlQE
h7ye9jVA+fHxEVGLaiZZdq0DegqQMb1lWdDZWBDT+22rN2RdVhDT14MyYX0N5C1Ni3sdfumdjVrX
dvDoFdoxi4K1ZIJeYttgqtWIuXZd9r8KLdNHr7csVCtXyx7WziFgcPmtnBUDC/MTF9otesuMpRXm
emt+xUHcpJMEX0FbZtKImatAEwfe5UOR8BtHThT4kYNJp4zhewcK1mfQZ1AflNUNI8WfmDblDe+g
AE8GhIeEZVtebGhZqERwwx5E6w+qBTlFTL7nDX5WrpuSNCTeVhFnu2yBmxPzZ6FJ8F69BarsDOt6
b0OVf8qUKpjw7yqXBtjzm19ab0THafnkM+HgWu2APJK7JeRezYmigJpMEwPEaQtig7hgNO4jQHmm
4Z6vbFyjFbKDW1t4h9uzIu074E1Ivy7oyzgMgv6RsUDc4MTbokrgd+ivccLvc0KsrPO7otCaocvC
bPwOPovSCMqbna2myFkTkRaNaYtZVJUxcHR5A1CtMr1EmLtruEUG/E2hLEkqzHWribZXWcuWD365
BEVqWN+gStGaJiwBLXli4z97eLP/Bq+c8Ev6wCUI1OK9fxCyW8dPInEZBe38i9PLVZKMLHgjp/fr
ug6N3J6O32vzXTsjDVDm2NDI8CCzmelbmEKr6pdyyKpglT9Esb+xjc0jUiM3SZTMxU41lCueLVMK
D+viRrgLRZVA/W/ix2gULx6uLhxuUuC1h8AErsAZ0R7EDq8GyKRG+D34NQp2MgITvQW5clCVkr4j
jjVEQcSTDXHI9zgt3ibnvGB18OqtmP+A1GqOrH94V6IQ3qJf//IGBykgsrJ+AY6gcRIZuimGWBt3
Aq7abg/3U8SBz/OKlZJ7iXZB1DIKIvfSPxCK/94Hr86ngUfAKqrOq9UEQG5TNdKNjA39we86kfTw
HyjBU0u4zTP46qBLyw6siJHpvyTgLdWwh4m3r7fEVmu6bcF/XJxD6fRhND06HV8ax9fTw3QjBpIb
hB1xBb6CDvr582fheNmdJr7pwzeAMpVgbnvKRZsQ1Qi3ItEiGSbfe8UKfzKdFXRQXACIv+58isYU
dkhFY/l1OcVHod55XexBZZ6C5NVQPsf8IRaR+Alatl0mvAdRIlS2BqW1+LUNAdW6xuKPomTu67xi
7u/tyVj1x7UnjWq9Yc7DcV7I34tLvWCBT6SP1SbI3fGCJIZIG0a4r7zWqbqsXiD5PClewGBiPWHi
n3KkhR3nMn16i3YN/2mbGy1QWymkcnoW90qBVEgYtPgZ0aDd/vMEKGNkQJ0w1/7wzVjPkkaWJvxG
Y6t0RcsqNr0t3wyZrSG59SZqnYyNn0aX08n0BNZ7poydy5L/U5JI3AMl7N5kzAKXew392swHzzPx
X58xmUkRBbj2Foxs8xo8zAVumo7nNMv1J66jUv7Ch2yMnip1bvkeUym+xsWwUUFUzXVEhJBoWqpX
/D+ZRSmAbToAAA==
BLOB
		;;
	7.0) cat <<'BLOB'
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
BZwxw+6BKnbR2ipuzlfERXgh/wY3O9/Z18AXtlv+QFFzdHYjijGGUe5qWnlXFl+euc613PVADXjp
30R7JbQHAiF0X8cgUlFpQ/IxRXgnth/LbGrgCT4+dybNgEuz2BGyXSfczRAAfXTGBDEs3s+5g0Pf
ZKhJEGe5S1CiMqtBiC1YqlGELS6CpRmexiyF7nazSOS2UY6D61j4ZDz820xMndSRAtXefoTxflyr
8Td4+DfNTT9R4YrGRxUbaXwKOKPxrQNVBLH1nlrVNNqGr2qxgBj8e0nPTpyOxUJniN7L09CE6LGh
9JoqLqeFlRQTokj2y/GIGtGdDYYx+GuazaWAs8cq7C3D7QjclwBNSrWsU8vo8Zj1sjrdZAKJBf5J
KBagjj09PWGk4xkuylySTGcheKCeJwjWw1L0JejF9O6V5METZEwFG1aTp1GSdiuoKlqEiVbcw8GP
OoAog5+g4Qig8ImF2luYgSCo2LsxEIdkJra5Aoo/SiWMFqNFPF4RxnPhuOD3Knmfz/QMu7VVdoui
R8S2Av8ZQhRxXUNs63SajfiUoVTK6hisHgIety2QJPKM/jyVFP+uDJmU4NPI729Jb71PjR+ozHvE
uKLIt8aVm/rXdINiH9tsq3VysuJm62W3XnbrZZ/Sy7ZadTr9hms35WUzLpQ9MxdaeT4ulH0xwXTb
jS55vm4bzzW2nm/r+bae7ykNrNfQKL7sNRr1red7Rp5PU1t1jVwf3DV6W9+39X1b3/fEJqZp7bY4
NNJ66tb7PSPv11CbTeH94K7d3Xq/rffber8nNrF6vS3enK/Xe9tV77Pyfq1OqyO8X6vTa2y939b7
bb3fE5tYp9ETb290MNLYer9n5P26zU5LeL9uq749Vd56v633e2ITa6rwj96SUtXW1vs9J+/X1Fr1
njjs1Vrdbey39X5b7/fUJlavi+xczXpD2658n5X3a/SaYuXbbKraNvbber+t93tqE2s2G/SqTLPZ
Uhtb7/ecvF9L7bWF92tp21OPrffber+nNzFcVKH3a7Xb2vaJ6i/+RDW/C/cDHgRAZnSlV7MKy+Xz
1IV1BY9Tq/Jx6nXwmaepewetlnxjpa2KxFFtNZ2oxJt5umyt+1NT67Y7uuvb17oJHMQk3tKT+jy8
MebA5EcbKPyGXlumi24ZoQH3d6FvyBfSa+LVpIuxEjXnDr7/a0mtWFfL/vwz9uvJC3FAVPSOa0YC
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
W67D47mWBp+Ph8zEDYEfMkGD/xf3SMbHknUAAA==
BLOB
		;;
	7.1) cat <<'BLOB'
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
ECdRvWMAAA==
BLOB
		;;
	7.2) cat <<'BLOB'
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
NRta9UtGzhWueKQqS186yYXDhmjCwAgWmvxTjBBiC5rka96J583ROkInjLgb5RP2U8rSP4MalOiX
JCjbOqHPLW4CL+IUjm8k9i8vTk/MdzndJNpaXRF27k5B/Xrn5HX2hvVO8s/HPu9kSlJdZeGScfjR
AX53kMMj3Jlcz/Hd9rI3/Vz23+VV9xxf2O0YQ2Zgc5Yhg0itiaaBl650nFYcBKiUr5nLP0RJiFMp
zWtvZty0WSZ+hqbIdObLJoZNlhdTd/XVZrteviPfaQqr4KuzaIlZNFTaPRSX9JUJaDq45iS4Iv9n
2jbkpKHigoebJHvH3nQKGUiVvUxcYHnjVlf69Nk2z/Mx6DqRX3wbfachl+8j1CQmkL/hIhbgRr1O
EqjX/39I4Otw4/wXQJp5x78w7//cYE9wPW9V4FAiz97RLWSBMxbVUo9VsT/VVnGxrIiL8AvBPW6D
vnXuYIrsoHwFjvX6JMkbRDOu+MqHmlY+kM23lx5uGdBkUJgvgnuZjZbeDXUdU4e+AWi+V1TaqnxK
pm9FslJmUxO/Z2CRl2g0lxq+L8S0TU67IcBtItwShHgP7+fcxanvMtVlyGN7MaZRrMY0kQe2NcrX
xUWwdIWnKUthuINVJIKkPAe3sfCL8fAvMzHz3pIUqPbmPcz3/bry3uM70OmOC0IWOKu89eOGUN6G
1qaMm64prxn8e0EfhVyMjIsBbv6iT/E1tAb6HursxBjq706ubwfjZftryGETjiOK5aY4vntHdJf6
IAUXO69SVqvvSdib3EeatWz3OnVPPv7ZzvuLXXx7KsCPQlEAdeqE6fspQBXhlziSbHrjgV8L5OkR
aT3hkO+Mll/VIHMq2LG6/NRm2W8NVUVLMNHGwUD/0QAQRf8JOg4BCj/HqL2BtQGW+8N7E3FIhmKf
CWSS76VOJXnYJj6vCeRvxXVhN+s0fj7nV3iurfNcND0huzX4z5Akba93pKHVO7DuF5ZWWFphaV/e
0jaslen3wruulysdNq6ZzaYqbFncFLZc2HJhy8+yarbABMnS4KZbWFphaYWlPZOldVv1Jllat9Uo
1rTC0gpLey5L69VbDbK0HuSEhaUVllZY2jNZmqa2uqr4nkhtq83C1gpbK2ztuWxNq3fkt3taQ20V
tlbYWmFrz2RrjZbWkG/tWlqneJtQ2Fpha89ma512T8SQjU6nUdhaYWuFrT2XrTW1dqsjXqxpnSKG
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
BLOB
		;;
	7.3) cat <<'BLOB'
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
BLOB
		;;
	7.4) cat <<'BLOB'
H4sIAAAAAAAC/+09a3PbtrKf7V+BuNOUsh4hKYoS87pVbcXx1K9ryWmb0w6HIkGLJ5KoQ1J23CT/
/S4WAElRlK2k9rnxjDIZkwQWC2B3sdhdUNw3UTghbU2npupb1PM9temrFjy4hu82Xd1ttlu+oQ8t
1XF0chxOSZ/OiNYmqvoc/xNdVbXtN4DmOelGU2fukSNKfhk7U5e8dLCgMR7+fDlxgnHDDSevt/ed
hD4n/fm0RrQOOXUTQKGb8Oe5aj1vGaSqAsrt/nz4b+omz8m/zrqDvbd/ke5VGHgkTqA1ccMoms+S
AIZzFThkCLjDebK9fRxMg4kzJpMgCS4drPfDiPROj8gVjWJ4bmxvvwk+koO3/W79ujO6rl9b/sf6
v9vWNVH23vXqbCh1DSigdSoZpHk98etGdNWqz5rRrAhpVba398K6M09GYUS9+vDmOTkcB/92yCC8
gpGRlwF7aiT49POEcjrU6/Vt8p5OvWd/wx+7e3bYGBH57zMhGqnm653xOHQbblpvdki15F9d/ltu
O8pw64u46UfqzhOKY3ChXmsK3HmgkROP0v4zoMWeEGi0ehbjcRAnuVkURzKZj5NgNr7hOKAe5GGh
gziJktCTGEoAkpsZjXNzBdHKkyYPejWxPepLWJiRxmdUgBHUYXCfiWWUkr2UD9uEfkyexTRmkiev
OHQ+cQCAZTF91ud0z/8DgBZBBiAE+7MMYeYgZqOZfeVEgTMcw/RdAcFkpC67iXxX65jtPJ7PpGmR
pYFvswXuB4CIuCNnekm9GtENlQTTmEZsVcVKtVIjLYt4dEx5QR0WgRf4PqnXL4OEOM+Kkj0slmwH
U49+JLrTHLY6uqXqfrPR0E2/3dbNoddxXaKpqmkYbKEs49uGoZbg/PlnUm921BqQhl3aBAre9072
WTWbTER2EfqSJigp9vDGdmH8iRJME8JKKi+2yTb5AQQjmFLiRJFzY4NaSRQnuqxswb/377pHdvf8
XMGSGkF8U3ptI6yiViplze04+JuyFjXC7ip3oUGgyna1FNP0EsgeTvmQbkeUg2YDS2nBphuiiuWz
+/sK9OYuw/BiNRQshQxQ9OSOnTi26TSJbsiuS1c1dwB0FoUzJkA0LvRZjqpG3oI2GTCJJrtZW+hh
haBJFTlcLhPC1nSaTdoyDM1tq43GkFpDq90yQN7oKmGT7YviJsuZwLXaTN7gLxM3YH4wdcdzj5Id
hGTjdpIwAqW0s1SZ6bvlumGQxDRhNdVCTaqR8o1exsHl1Bk3Rq9RgAMfJIe87b7r2Rcnh/3Bvv2W
rw6zCeOsNk2jZuhsebAtNXA50/ZOj/b53cnpeW9wcX5CcNvlY53YM2cauAouGLGaJqDVnEtawR55
0/3eLxcH5OlTwkXXU3AQvx4eHVWWSg96g7PDfWi99SEYjxVYlrPAU0CK+4cH/d7BOyZOP0Dngb9d
36IfQWg0KKpu2dn9l+3qdjUVubWmETs+tWkUhRGT6Px0wFyYOEmNNBoNWHyfoCe568AyIruxGwWz
xGa6cepMKHlFTi6OjtiA5iDrTd1OiAAZwxynIQCoL9j4toA4CqIKYsE+QAhLkrA+tpbxplpK8NpL
K9mQkQZbxa6W2/AqDv6F0HFMSX4gYIfMwDZZbyAcODeQu0aRNlgYBVLjyrGZIQBa7TJ+wZ9BDCNU
snGNcC5UOOWQMcO5/y9N1Y2/EDqezoAfia9AMdenId5XZNMaYhYIADkMScmV+KJ5nHggBTU2i62d
P6dvnAQUEsrFc/JjDOqL/QUjkk2A/Oj9Od3hsKxbvCmS63/I+/7g3AaNrBSqKuQ52bmYfpiG1xLL
AuHEyJ7tgoFNyShJZs+fPYvns1kYJY1J4EZhHPoJsxyffRg+0yy12dLI7jNQDYSvdBT33w5Pmjqb
oD+exyMxP4b6B8IXUXVh7ZAvTFV8jQLIVo4ii0bUmZFd9rfGFUy7VdPBujE0raYZX6th7uhAKgOy
xbjOlhvbJ7dReBWGqEIYINvD61vsrv46BNPfH4fXIJraCyjlViJsMZ/ggT9xVTAF6z2ZR1OlZ/fO
z0/Pa6x+SwgU3o8D8CxqUiksKRIpewKsoBE5NiEOEh9jPUpDVlHNyjPVt4XzrbDxfxGbpZO4I5zD
F8JLxLwUhFqau5rOXbhLHC6nU2UXXCrEBiJEijFWa2odtnVoTcPklpVgrNgQr50btrHjYkGe7koy
4WaJfCxjKklZKdgKoz3u/o4mEPiIbESyGKl5fGx3jw4PTnr7dv/wfY+bSqS6uhKUg+zWo8P5JQzS
DyuIl2nDi5Pe72e9vUFvH6HJSxJRZ2xzC+xuKSE7ZyFY9sxKAaVCL2lEUrKDBpnQSQjChiTgLqny
499zGC78rezUykedDaD21dPivCyX0O9vqGRri9NT7KQEdggp9ih0bVNHoWtb6oLQlUrY/JLeLmHA
Xhzkm8Ojnn10eNKz96FLjmuWRGj7F4WC2dJCMP5LMsEl3xmDQTcBc/jhOLrcEdI/p7qAm0eHx4cD
ZIZuaszIreqm0SrxrXYFbbv9wV736IjYFOwmbz5bsLDiJQbs5UqQ/qAJL5MRLHdoDvdKXLZUBVCV
aOQVaLeH4QpssYQTTGPk4n3eKztW9YB82JoBERROtwqQc4It81Mv0PK8d9T9w97bK5afnh8epJWI
HYbizm4UtjZkr1WmajmbdYuzWfg0a7B5usTndNWJ4eaHBAPgULPSFbfh7X3zNuWs0eScbWtrcFb6
Pncyt7JhaIGhS+ws02EzRg227yFBkEFW20D3XFX1AoMW97V0Rsxtms8yPzYFc6bemEYxbIHiroZ7
5lfY+2Ak2qFvc0Jw65pZ2qToP5Gd03lCQl+QDNykomlZdDnSSfGdl9g2HzYnWiZaldtDPaOSkIyM
K3aGw07LaOodb+g1Gjr14H9n2HQ8//ZQz2hFqIfHFg1giwm+DVw6RWPEmbk8SoaGriCXmIvkyuU4
HDrjmEcDESQLcJCHCWMwx5IwJL3fB73zE3tPqeAOzztdQd/FE4HhqhpBa9/wVd/RDF/zmo1GWzeG
Jm25rgHu3wpaL2IpUnyxFp3KZrumqbAu4KprjPL8OGg0TzzwqEULcBq5Dwhu9KdPn5h/DPbl1qVr
u+F4zMKQ7o07prHCDc/M0kyjIxgEgdYT54YMKZnH1CPDG5JTVH+DPrSdBGqByExzBEnaOzrkIkJ8
cbLfe6M87R0ogCQSjcVSFDZ6KdxHl+LJVgEWllZMkxX4YvEYURYuCKYsDKymgZE1m6zV0RqIVyIq
zmwFsmWwSmaXck3OY8qwioDm1PYjSkURljjgBLBeF6BYaMiJAUBIDIb5q/+U1dBLbvKMirAH9N6y
9Xrcxbggg5AzqmTxQjmTa+p8iKgfp+NS+PlDPkqB8s9jzE2zw/XO+tKfHsvZXhC7TuQxSvvzqYs0
Tlh0HWgDZTN2Qhon4AbYsppFCOfgFvDlUoqJx+zL0WAdLUECa9CZwqbFtt1oCv6jgBQRxSXeNQR3
h3P3A03iXNi1BDYJZzzUQ7JFLTu+wg3T/QBeKPA2vOHUXqEDxYHncKlIaD3P0Vrq0GtbHcNtNKjf
9Jqq5g211srDBNG8qO5EMeOzhf6V1b4rvpKGmzOmuCMKE8ONJa2d9nl4DA0PfCAvX5G3A/v48AS9
8wonjnDBcxU58hXdYUTzmqPp/s7RPIxPPE/tLeGvYt+pyvgFxaFSfL5fd/mbx5DzpOWRRxajrXBr
r6WxVc0uWnPB2EtPvpacrcLxnioNDcnDUSKMrOrdyFYeFXKceP6RO4MbJbCwlgeA9B4l9ddThOvz
UJ3GSnNjwnOar5/gsiwzgS0OiuYsR2BCWl2Rfk8Hg0h6x1qOIZWQBNfTDPQE9ezLKLxWFvqTYxjY
3X6/dz6wz/c0ZZSkBn6BFIWV8t9ZKIUx7BL9/3nVfNOAuF9VaFp9VUD2gjOj3xvY+91B1+7u758D
E2oEtiKKo9IVqD8o1EOHrBXwBCzjAtNqUhUed/u/csCLvgxoYtODPfvNUfegz57IU3LYZ0fw4IKf
9c77h/1B72QgZU/TTHTpNE363OtInxeCaYbKvCh7W1szykweJRx7tuckzlqDKezgEWUXKbXpPvld
SCbAigK59r8/YV1vjCi/X+6wMEbLtoD0YX2N6l7TMDstr9VoDDvNptG2qOOAJ3SbhTEqtzBGIsJg
4p5jmYX4AntZY5U0CnFZFMW85/rtO9eLf75RvfhH+4o89fqKUcycIBJvr8AfrUbSe30B06KVxseO
xvASJVcIiHxdbrhcJkTEcHRX16nZ1DW90VCtVotarabjNFcaobJ9UUZkOddZGOZgl86CkGTxBwRP
7eisiOyOUUm58ygCJwA25yn9mEhzqLo1rr8eUccjOSMeihInGGdFhBUhofjB5W1rKPfG4LC0WBDK
aXb0tqe3PE3vNBqONRx6TqvV7BjtVYTKoSjSKleF3pmuYdBO1+6y2/PhIFRbjueBno/tyzk4VGAi
CoAp6KmhDLJmp92gj+UbFvnWSg68RkLfB8e7Rp5KvVcpjcmmtQ92nlU0nJcHee8nW2t1mTk8qrQx
xDNcXoh4Ew/D4uWrOcrEo5STYiTpSff3y9If41KCite97pmZ39bZHWxcoS/SF4iHJYXynVRd71Bd
N3XX10BXeB3P11XN8Q1zla5IERQ1RVrBpMpU8fSFX6DgFxRfnMgVOzz4Jbhku/Bu5Ri2m9M96c7w
YmZzKB/rWmVXFF8chSxsh4RggvAkuhLu/Nab817P3h+cdm1A86uiYjz+Lnngo1EqxHfYa1skCeXy
omK57XAWr+Lxeghk4BUsTnY/plM29XWmmhldXjhn3h2pE4170qZmImU1s0jZBdKmlIVedxdx8ZEV
CbmKkvdGyn9My1wUG+Wo/voDzPfDSvmX78cPl8uE9LeHHVdtW67R6niNht/uwGIYml6z3Vwl/bJ9
UfhlOdeoak1DlaqKCD4sjbmbCMMMjSNG9B9EtIT5XG+7/bf2eQ88O/RsvJB8In+iccHPGuWB227l
qYBGv48BSwP+2Ik/VF7wVvm3QF6l+NGnK20CjLbtCdgLAfk4mags+MEYRZO/aRSCEQo1igTMAbiT
Gf2PTWdBR2GlNWws4bglhXED/rbR61fENNh7sQp/fkrUj02/Is5JRSsxcyZ5/NAPRG4uRqCIMe5W
Zotd3QaqzKqaWfkq+Kb+dfBGpwg/Y767achHnG49V/KFXI9A2LkyIE8YAVhNdWvFa1qmwTY6DiGP
G2borB+evOseHe7bh/u/i/ftBSLp6YpG67GXQa7FXwb4DQxmzQSHUSWsyeK7YJd4vEaDRSav0WCR
y9ggx2Z8XuQzK1rN6C+4UtN6tZLuFLfohT9X6br0Bz7DkkIZxW+a+lDVTAOs90aj6fiW6rXV1rCl
r9J2KYKiuksr8KSYvyrFL9KFencMYz/ZP+qdK52aPOQ92esOagSu/cHnwfHZu+755713JQV9kH7l
5NTGCpspNPYTnuywnL0fyd4+PuqdKOFMY6aHMBO3St7HIK85NAtMQgvYSnONdWwszci7drvDdezz
uza8tZGIPY8JVhKlpjO+oA+IEvaqt5g9vqHBXgwtTqzGBA5RiFdlsre2oRZaQLta9ip31mwJU/rO
lKFjWIVdrIdi91b+xwh2RMfUifHnAGI02bSQPvkj7aIALAnKuuJwLyys3sJCbvcsj++r2bjAQG2Z
gbzodjlYAv9KqQCdwn+LpmvNRblg73Zw1nL+SjlpNWtZ1GkNaZFq4AkO4rAPWx97y4M5g5JysPUc
7IG6fLN3enEyyMphA9KEnbueIqn+I0Xy4JLz/7P4ifxJ4EnvNxsglN7v0O4cgFh4oP4anPn5OGlc
OQwFp6SQDH6ir+sPKBkbjfGYNMZqKyb7CfJwRYWMXHTaLR9cNUM1nEaj01Y12m5Tp+PdZs1kSEos
mqwSf+poNvHIGq9W8cc9Qnr5w+nZ3ul+T4ov6J9BIZxeFGab7Xj2RqE9ToUGEtHhkmE8oGRsFNpj
M4HahoUaA67tZblYTxTyUsA3Rb7h8XYbjfE4NQZIBGqMdkt9QMnYaIxHpzEslf3Ur9q2NH3h9O2f
bB4LwrGJnXxXsRNguIWKwNK1b1UEdzN8owgemyKwrBa+hmJZ5j1uEHvvUpf6/cZ0eJymA0iGxSWj
/YCSsdEYj01jaGrTxFex4KZz38aDEI+N8fBdGQ/A6TbG2OHGum/zIcfyjTJ4dMqgaenoYMINGBL3
sE0IazIXl98YEI/TgACRaLaEbJgPKBsbrfHotIZhdrgJYbQ17d5MiAXx2JgQ35cJYZgWNyGMtq7e
mwmxxPKNMnh0yqDVbOEr23DTMb9VGZQIRS5KvVEG35cyaDVN/uOnFpiN92gZFFi+UQaPThmYmorv
7MCN0bzvbYJfNv7EI/UnTE0zhGy0HlA2Nlrj0WmNtmqo/Aum6reHJMvsyixavTEhvi8TAliOxxNw
8+0hybtZvlEGj08ZGKrGJcMwzHv3NFE8NibEIzUhQDY6QjZaDygbG63x6H5F0mka+OV9uLGs+zAh
QBoWf1zwfmNCfFcmBHBafPGxw7SC9VAs3yiDx6YMDLWt81+Wqu3O/Z1PLIjHRhl8X78tVdtN/utS
lWXBsB6K5Rtl8OiUgdbhnqahWap5T9tE/g36XHBh4088Ln8CZKNlCtnQHlA2Nlrj0WkNQ2vyNAYg
Gq373E8y8dhojUeqNUA2+I5i6OoDysZGazw6rWF2WtzxMC3dvK8oRO6V+97G8fjeHA+zY3ITwmSv
S1oPxfKNMnh0ygBUAAarDatp3K9LmorHxoR4pCaEpbdbQjZaDygbG63xaD9uA/L8LKZxDASQV/wi
b2m5TOjmD03P012v5emNRsdy2oaqOpbrWIuftinHwb9sU16HAXdNJN7j10xk2Qd5Z6OZLcDtyHe1
jtm2XeDM0HE/KPNpHFxOqYeQ9IpOk5pIa4cPIkXDVSg+11yGK4yCyxRhlpKHfVT+FbmzgSI6zXcH
E40ckYGgzj9qe9ZXZHM6Zd859YQEr6olnz+TJJrTxRxBfFzye+4LXJ04wfRZX6aMyz3JT7C3HLPj
d1yzo9JGQ3ObuuqbtOk7hQ/L5ltyvuVL8GMzqlXTOqTKrjpmzmGV2RfqY2cW2B513CS4chKa5sj5
IpjQP1Ai+p85jROeibjhzJORzfKPicnyDBu3gOGqXV2f+5T97X3OnDi+DiNvjX5T0Fv6ljBr9+8F
l1CyRu8C8Ja+OcQ6PbvhFBOEse8D2958dnv3S9DlYyiCrTUQnqRgDc4vQK4YQA6kpHOUyUnozce0
kYmm6LW8UinqTVwH7E+2wviTWGHqsNkc6sOW6VpOo8EyYKqab7Wbpl6ywkTL3AoTJWyFdfiJA7ug
Njx7ewb216H9S+/g8IRlkNySJb2Twfkfyo4XxExtZLnjdmqwkezgXwna/6M/6B1DCeY8XY1DpIP7
BgwT56PtB4BiPhuHjidQ6GoJks/y8ax3vn94nuKsluHkCR+cKLGHoXdjszuGe6eufQVm5rX2B/t2
SsvT06Ne90TZYZv8tT2PxrYfzuiUodxBxEvTPp1ezEDD01/CcAyPhYZQwnYLl2VFFJlGoSj/WLl7
CMHUHc89ymanft0YRMt1RoEvvFgm/9WNZWq5rIasrVxYaVZEvqF688nkhtNxyw8jogSv1BckeHly
cWwPzrt7vzLztA8l1ar8gDvLzGLPksj2WH7Ep2cHyihJZulA/hX8JQywZ7vkmGeCdFwXtluWDZLn
fVwYEE+3q1REqs+FHJ7lyPn37sH85PEGntaRJx7EfDwqz7UCV+Fhr0uFHwLfoz55233HvlAP0+9B
N/wGjOr/veiBAd1/ezHYP/3tROl33/QwafRJ97i3rN5mDihwMBmm8Rg464EVd0cD+TSPAgCWaY/X
bDShySj0KlkGIZayMjcPJC7Pzvn1PAEucEUa21KPepUsjwzg/PLlCybHLNGtDC/4MwFTQ3GmZAvF
QttqHd8cmmDUuC2r0XAtXaWG16K6Y5Ro2yKKnNotVqFYaPjGD79w/ZtaN3zylyzLZpQ2xBTAyAUo
safOhObSEslb4LD7gTWJpV+UJT3AOaXBMZ6siKU8VZ5ezlwbvKsJbG4y3pVV55IxFQDRRWOolVy5
PZMODiaWYrmBbOwZ/sK+mSjxzQSziWo1soCvkubKlqkZtnJZlWQeovcs85my0O6FhM5rAnsaXroK
lMgEgSLjvW49ILm3SukgJ8xcJdi7wM3PkQBJIy42S4idI+uTBXQ5srC+k8lMZKpYYCUUSxau4CGH
4JjuHu8cdwL7jlEDK3No81lZxVTe24M/znr2mVKYErAc4z6wi4KjniZJb2Icml8ejFnCJb99gE9e
pdn2MgaUidpiO8maPG+KENWt1VwqwooBLxJ2q9876553Bz0+vlWNxOfLUf4NKf+pO4U3g/NeVyRP
fHNxsoc+LGw9DhhFsGlQh3udPO2XAyOAbvtArNP+4Hmh7KC3VLR3evrrYe85UiQvqngv6FAuqhIC
IyfXQeKOiOJElykjysZSzp3lrTszJ7DtX6WWuPCYs30iLRA7BAUqaZarmZ5pNBqGZZier7qO3jFL
doiscW5vyAoxSmHxlwLhohmFIAVTHWCdzqeeA/ZFzmCd+z44JLsxHfs1kR9eguXyxso0a9V8qqsh
mHi4pCbBBBb8KJyPWZqqK2qPvGgh4zxbVCJjrED4BPQD44A7mSl8ye3scRetvh/EszAOePyLMfjz
59vAB+DRYZyMpZCV4xMpYOTYLmnCxgTrdzyn+XR0LNkcjeTEP1AUKTQDgDogH7w+RoMgR80i/WwB
t5Kw+Qx4HBbzxOLiEsnrDaNV08wC2+6no9xmvoskAG3905/qT1zRYHIRLK5WX5A0u0YQxzPHpQpv
gTslggORWE5dYAi40QqL9QqFFU/YcGRkcgYehxcrT2F4nOw13kdmUP9K6YyE0/FNSuVrTLReI87U
I8ElO3Yj0Mc4YHmNYmlT4+a2UupwPEI7gtyskIBdyXcET0O1fGpp9vDFoHD5xLHmDgpmQUAmZpWM
oDwByteQLR+rZoRIwRouS3YDVD30yTQkPz3/CUhLkhHFKQJJPcwSNYvoVRDOYywVOeDvHoGYaz5M
jnE2zahpGqm29A67ZpKbrT5nxijPYk5CHwg3xw096Izsyju5Anf5aPEhTsJ80rZYqKD6QifxfCgG
Dvh9sY+jzV/DBYT2BZb+Zx4mTDTWbp6dCy1iwA2EQ/IzjlyKaX70wo9HUhBmHHFItlDYqALGTYE/
4AfW3GNFT4QE5CUe4jx9SnAs4CoyWwL7f0Gq1UBsYhg4kgCv2Jr+8yfMJSQK2VCyClgOCqLI4U0h
+Nwq0ohqGSbbQ6otcMIX9pIy1grarcNfFvBPU3TxwbzCUnFqD3ewhJg6EXwvMAgPbhSWBA7ugETi
8IKPHpfILe1Km5AFwygdJUwDRpYNTCxpWQUUfJIqSF5WkZZFtcoLhHNfv2tMDF+dpEdSt89BJI6s
KPmG6eGOSCiMOe8s/MVxW+2U2WzMaknP2NBqk/F92HpBU4IGHrOgJyiUT58+cUWRP7bAEwS063Kx
zIWzjjE/T8Xki+yZh9xsF7O2sojR4cmgJCKHBGDwWSStrE1pxI2vujIxZGkloykYdmmRcFcQz/Am
4RvEEhgGYjBeJckjRT4h4m4VAGNZBoWP4nu2Gh5/tlnGO+1+OCMEJkuji1vDIgFfgojwnWyJsiwm
4jAXezZP0MVhp3kZvxhHvixzZRxMAtZ6ER2aT2x3P6AJbj/SmOQjTZ9wbcF/pRiYB8tOAnGG4n6f
mqRCP7UtfA2to1n3R0SZN9AJ8gH6LZw3Vwdq/mWAen0lhXmIk5/1eqEbUV9h6GqkZ//WPT85PDmA
WR5LEUYKEsRDOFHpR5eCc+CRH70GGYSwngAHc1f4fs5AYKzTS0pWrQV2mgxjaIBT1NipLbFN2h6X
IdgEbP0JbnvhlEpDo4qTLxqDbqbnQNG5njxC/z8BOvRBK6QAAA==
BLOB
		;;
	8.0) cat <<'BLOB'
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
BLOB
		;;
	8.1) cat <<'BLOB'
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
lr3hev0cFME1FaXYMHtX9KtYIv8fs3551YjCAAA=
BLOB
		;;
	esac
}

main "$@"
