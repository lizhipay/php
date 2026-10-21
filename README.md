<div align="center">

# PHP Security Update

**One command to fix the PHP critical RCE (CVE-2026-109618 / CVE-2026-109619).** Auto-detects every PHP on the server — BaoTa/aaPanel, source builds, distro packages — and fixes each the right way, with source-level backports for the EOL versions the PHP team never patched.

[English](README.md) · [繁體中文](README.zh-TW.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

![PHP 5.4–8.5](https://img.shields.io/badge/PHP-5.4%20%E2%80%93%208.5-777BB4?style=flat-square&logo=php&logoColor=white)
[![Advisory](https://img.shields.io/badge/advisory-2026--10--21-red?style=flat-square)](https://www.php.net/archive/2026.php#2026-10-21-5)

</div>

## The vulnerability

On 2026-10-21 the PHP project disclosed two critical (CVSS 9.2) vulnerabilities allowing **unauthenticated remote code execution**, affecting every PHP that serves web requests (PHP-FPM, Apache mod_php, php-cgi, FrankenPHP, LiteSpeed).

- Advisory: <https://www.php.net/archive/2026.php#2026-10-21-5>
- `CVE-2026-109618` (GHSA-w8hw-w9fx-j79w): on out-of-memory, PHP `longjmp`s out of a half-initialized request; shutdown then acts on the invalid state.
- `CVE-2026-109619` (GHSA-6wmf-4rv5-p3rp): request-owned global state survives into the next request and is read before normal init (use-after-free).

**Updating to a fixed PHP build is the only complete fix.** This repo does that in one command, and provides source-level patches for the old versions that got no official backport.

## One-command fix

Run as root on the server:

```bash
curl -fsSL https://raw.githubusercontent.com/lizhipay/php/main/php-security-update.sh -o php-security-update.sh && bash php-security-update.sh
```

It **auto-detects every PHP install** — not just BaoTa — and handles each by source and version:

| Source | What it does |
|---|---|
| BaoTa / aaPanel (`/www/server/php/*`) | rebuild + patch automatically |
| Source builds (`/usr/local`, `/opt`, LiteSpeed lsphp, `php-fpm` on PATH) | rebuild + patch automatically |
| Distro packages (apt / yum php-fpm) | **advice only** — update via the package manager (the distro already ships the fix); never recompiled |

| Version | What it does |
|---|---|
| 8.2 / 8.3 / 8.4 / 8.5 | upgrade to the latest fixed release of the branch |
| 7.4 / 8.0 / 8.1 | last release + the **PHP team's official** backport, recompiled |
| 7.0 / 7.1 / 7.2 / 7.3 | last release + **this repo's port** of that fix, recompiled |
| 5.4 / 5.5 / 5.6 | last release + **this repo's port** of that fix, recompiled |
| 5.2 / 5.3 and older | official mitigation settings only |

Common flags:

```bash
bash php-security-update.sh --check      # show the plan, change nothing
bash php-security-update.sh --only 74,82 # only these versions (version number or install id)
bash php-security-update.sh -y           # no countdown, start now
```

### Optional: session object-injection hardening (`--harden`)

A **separate** issue from the two CVEs (the official 2026 patch does not fix it): the
classic `session.serialize_handler` mismatch object injection, where an attacker gets an
`unserialize()` of a controlled object (often via `session.upload_progress`) and runs a
POP chain through `__wakeup`/`__destruct`.

```bash
bash php-security-update.sh --check --harden   # preview
bash php-security-update.sh --harden -y        # apply
```

`--harden` rebuilds each PHP with an opt-in source patch that adds a new
`session.harden` ini (default off), turns it on, and sets a safe session config
(`upload_progress.enabled=0`, `use_strict_mode=1`, `use_only_cookies=1`). When on,
session decoding refuses to instantiate objects (they become `__PHP_Incomplete_Class`)
and `upload_progress` keys are sanitised. **Even a PHP already on the latest release is
rebuilt once** to carry the patch. Caveat: it disables object deserialization in
sessions, so apps that store objects in sessions are affected — preview with `--check`
first. On PHP 5.4–5.6 only the upload_progress vector is closed (object-deny is not
possible pre-7.0); see [hardening/](hardening/).

### Safety by design

- Each version is compiled and checked **before** replacing; a **full backup** is taken first and a failed start **rolls back automatically** — the site only blips for ~1–2s during the FPM restart.
- Every source download is **SHA256-verified**; the patches are embedded in the script and self-checked.
- The original configure flags and compiler are reused, so extensions match the old build.
- PHP-FPM restart uses the service manager where present, otherwise a `SIGUSR2` graceful reload; if neither is possible it tells you to restart manually (it never guesses).
- Distro-packaged PHP is never touched — only a package-update command is printed, matching the official advice.

## Source patches

The PHP team only shipped a backport for 7.4 / 8.0 / 8.1; older versions got nothing. `patches/` holds standalone patches you can use directly:

- `php-7.4.patch`, `php-8.0.patch`, `php-8.1.patch` — **official** PHP backports, kept verbatim (upstream commit noted).
- `php-7.0.patch` … `php-7.3.patch`, `php-5.4.patch` … `php-5.6.patch` — this repo's port of that fix to the older versions.

> The old-version ports are **unofficial** and not vendor-reviewed, but each one was compiled in Docker and validated by running PHP's own test suite before vs after the patch to confirm no regressions. Per-version change notes and validation numbers are in `port-notes/`; the cross-version consistency check is in `port-notes/AUDIT-concat-guards.md`.

Apply a single patch manually:

```bash
cd php-7.3.33
patch -p1 < /path/to/php-7.3.patch
./configure ... && make && make install
```

## Layout

```
php-security-update.sh   one-command fixer (all patches embedded; ship as-is)
patches/                 standalone per-version patches (3 official + 7 ported)
src/                     script template + builder (build.sh embeds patches/)
port-notes/              per-version change notes, validation data, cross-checks
docs/                    technical notes on the vulnerability and the fix
```

Rebuild the script after editing a patch or the template:

```bash
bash src/build.sh ./php-security-update.sh
```

## Scope & disclaimer

Linux only. Source recompiles need a working toolchain and internet to fetch the PHP sources (SHA256-verified). The old-version patches (7.0–7.3, 5.4–5.6) are unofficial ports, provided as-is; in production, run `--check` first and apply during off-peak hours (the script backs up and auto-reverts). The durable fix is still to migrate these sites to a supported PHP version.
