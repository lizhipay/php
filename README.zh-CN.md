<div align="center">

# PHP 安全更新

**一条命令修复 PHP 严重 RCE 漏洞（CVE-2026-109618 / CVE-2026-109619）。** 自动侦测服务器上所有 PHP——宝塔/aaPanel、源码编译、系统套件——各自用正确的方式修复，并为官方从未修补的 EOL 版本提供源代码级移植补丁。

[English](README.md) · [繁體中文](README.zh-TW.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

![PHP 5.4–8.5](https://img.shields.io/badge/PHP-5.4%20%E2%80%93%208.5-777BB4?style=flat-square&logo=php&logoColor=white)
[![Advisory](https://img.shields.io/badge/advisory-2026--10--21-red?style=flat-square)](https://www.php.net/archive/2026.php#2026-10-21-5)

</div>

## 漏洞说明

2026-10-21，PHP 官方披露两个评分 CVSS 9.2 的严重漏洞，**未经身份验证即可远程执行代码（RCE）**，影响所有对外提供服务的 PHP（PHP-FPM、Apache mod_php、php-cgi、FrankenPHP、LiteSpeed）。

- 官方公告：<https://www.php.net/archive/2026.php#2026-10-21-5>
- `CVE-2026-109618`（GHSA-w8hw-w9fx-j79w）：内存不足时 PHP 用 `longjmp` 跳出半初始化的请求，关闭流程随后处理到无效状态。
- `CVE-2026-109619`（GHSA-6wmf-4rv5-p3rp）：上一个请求的内部状态残留到下一个请求，并在正常初始化前被读取（释放后使用）。

**唯一彻底的解决办法是升级到已修复的 PHP 版本。** 本仓库一条命令完成，并为没有官方 backport 的旧版本提供源代码级补丁。

## 一键修复

在服务器上以 root 执行：

```bash
curl -fsSL https://raw.githubusercontent.com/lizhipay/php/main/php-security-update.sh -o php-security-update.sh && bash php-security-update.sh
```

脚本会**自动侦测这台服务器上所有 PHP 安装**——不限宝塔——并按来源与版本分别处理：

| 来源 | 处理方式 |
|---|---|
| 宝塔 / aaPanel（`/www/server/php/*`） | 自动重编并修复 |
| 源码编译安装（`/usr/local`、`/opt`、LiteSpeed lsphp、PATH 上的 php-fpm） | 自动重编并修复 |
| 系统套件安装（apt / yum 的 php-fpm） | **只提示**——请用套件管理工具更新（发行版已有修补），不自动重编 |

| 版本范围 | 处理方式 |
|---|---|
| 8.2 / 8.3 / 8.4 / 8.5 | 升级到同系列最新的已修复版本 |
| 7.4 / 8.0 / 8.1 | 升级到该系列最后一版，套用 **PHP 官方** backport 后重编 |
| 7.0 / 7.1 / 7.2 / 7.3 | 套用**本仓库移植**的源代码补丁后重编 |
| 5.4 / 5.5 / 5.6 | 套用**本仓库移植**的源代码补丁后重编 |
| 5.2 / 5.3 及更旧 | 仅套用官方缓解设置 |

常用参数：

```bash
bash php-security-update.sh --check      # 只检查，列出计划，不做任何改动
bash php-security-update.sh --only 74,82 # 只处理指定版本（版本号或安装代号）
bash php-security-update.sh -y           # 不倒计时，直接开始
```

### 可选：session 对象注入硬化（`--harden`）

这是跟两个 CVE **无关的另一个**问题（官方这次的补丁不修它）：经典的
`session.serialize_handler` 混用对象注入——攻击者拿到对受控对象的 `unserialize()`
（常经由 `session.upload_progress`），再靠 POP chain 的 `__wakeup`/`__destruct` 执行代码。

```bash
bash php-security-update.sh --check --harden   # 预览
bash php-security-update.sh --harden -y        # 套用
```

`--harden` 会为每个 PHP 重编并打上一个 opt-in 源代码补丁：新增 `session.harden` ini
（默认关），开启它，并设定安全的 session 配置（`upload_progress.enabled=0`、
`use_strict_mode=1`、`use_only_cookies=1`）。开启后 session 解码拒绝实例化对象（一律变
`__PHP_Incomplete_Class`），并净化 upload_progress key。**即使某个 PHP 已是最新版，也会为
它重编一次**以打上补丁。注意：它会停用 session 的对象反序列化，把对象存进 session 的应用会
受影响，请先用 `--check` 预览。PHP 5.4–5.6 只能封住 upload_progress 向量（7.0 以前无法做
对象拒绝），详见 [hardening/](hardening/)。

### 安全设计

- 每个版本编译并通过检查后**才替换**；替换前**完整备份**，启动验证失败会**自动还原**——网站只在 FPM 重启时中断约 1~2 秒。
- 所有源代码一律**校验 SHA256**；补丁内嵌在脚本里并自校验。
- 沿用原本的编译参数与编译器，升级后扩展模块与原来一致。
- PHP-FPM 重启：有服务管理器就用它，否则用 `SIGUSR2` 平滑重载；都不行时提示手动重启（绝不乱猜）。
- 系统套件安装的 PHP 一律不碰，只给出套件更新指令，符合官方建议。

## 源代码补丁

官方只为 7.4 / 8.0 / 8.1 提供了 backport；更旧的版本什么都没有。`patches/` 下保存了可独立取用的补丁：

- `php-7.4.patch`、`php-8.0.patch`、`php-8.1.patch` —— **PHP 官方** backport，原样保存（附上游 commit）。
- `php-7.0.patch` … `php-7.3.patch`、`php-5.4.patch` … `php-5.6.patch` —— 本仓库依照官方修补逻辑移植到旧版本。

> 旧版本的移植补丁是**非官方**的，未经 PHP 官方审查，但每一版都在 Docker 中实际编译，并以 PHP 官方测试套件「修补前 vs 修补后」比对验证，确认没有破坏既有功能。每版的改动说明与验证数据见 `port-notes/`；跨版本一致性核对见 `port-notes/AUDIT-concat-guards.md`。

手动套用单个补丁：

```bash
cd php-7.3.33
patch -p1 < /path/to/php-7.3.patch
./configure ... && make && make install
```

## 目录结构

```
php-security-update.sh   一键修复脚本（自带所有补丁，可直接下发）
patches/                 各版本独立补丁（3 个官方 + 7 个移植）
src/                     脚本模板与构建器（build.sh 自动把 patches/ 嵌入脚本）
port-notes/              各旧版本的改动说明、验证数据与跨版核对
docs/                    漏洞与修补的技术说明
```

修改补丁或模板后重新构建脚本：

```bash
bash src/build.sh ./php-security-update.sh
```

## 适用范围与免责声明

仅适用于 Linux。源代码重编需要服务器能安装编译工具链并联网下载 PHP 源码（已校验 SHA256）。旧版本（7.0-7.3、5.4-5.6）的补丁为非官方移植，按原样提供；生产环境请先用 `--check` 查看计划、并在低峰期执行（脚本带自动备份与还原）。彻底的长久之计仍是迁移到受官方支持的 PHP 版本。
