# PHP 严重漏洞一键修复（CVE-2026-109618 / CVE-2026-109619）

2026-10-21，PHP 官方发布安全公告：两个评分 CVSS 9.2 的严重漏洞，未经身份验证即可远程执行代码（RCE），影响所有对外提供服务的 PHP（PHP-FPM、Apache mod_php、php-cgi、FrankenPHP、LiteSpeed）。

- 官方公告：<https://www.php.net/archive/2026.php#2026-10-21-5>
- `CVE-2026-109618`（GHSA-w8hw-w9fx-j79w）：内存不足时用 `longjmp` 跳出，留下半初始化的请求状态被后续误用。
- `CVE-2026-109619`（GHSA-6wmf-4rv5-p3rp）：上一个请求的内部状态残留，被下一个请求在正常初始化前读到（释放后使用）。

**唯一彻底的解决办法是升级到已修复的 PHP 版本。** 本仓库帮你一键完成，并为官方已不再维护、但仍大量在跑的旧版本提供源代码级修补。

---

## 一键修复

在服务器上以 root 执行：

```bash
bash bt-php-security-update.sh
```

脚本会自动检测机器上所有已安装的 PHP，并按版本分别处理：

| 版本范围 | 处理方式 |
|---|---|
| 8.2 / 8.3 / 8.4 / 8.5 | 升级到同系列最新的已修复版本 |
| 7.4 / 8.0 / 8.1 | 升级到该系列最后一版，并套用 **PHP 官方**发布的安全修补后重新编译 |
| 7.0 / 7.1 / 7.2 / 7.3 | 套用本仓库移植的源代码修补后重新编译（见下方说明） |
| 5.4 / 5.5 / 5.6 | 套用本仓库移植的源代码修补后重新编译（见下方说明） |
| 5.2 / 5.3 及无法修补者 | 套用官方缓解设置（关闭 upload_progress、收紧 post_max_size） |

常用参数：

```bash
bash bt-php-security-update.sh --check      # 只检查，列出处理计划，不做任何改动
bash bt-php-security-update.sh --only 74,82 # 只处理指定版本
bash bt-php-security-update.sh -y           # 不倒计时，直接开始
```

### 安全设计

- 每个版本编译并通过检查后才替换；**替换前完整备份**，启动验证失败会**自动还原**，网站只在 PHP 重启时中断约 1~2 秒。
- 所有源代码一律**校验 SHA256**后才使用。
- 沿用机器上原本的编译参数与编译器，升级后扩展模块与原来一致。

---

## 源代码修补

官方只为 7.4 / 8.0 / 8.1 提供了 backport；更旧的版本没有任何官方修补。本仓库 `patches/` 下保存了可独立取用的补丁：

- `php-7.4.patch`、`php-8.0.patch`、`php-8.1.patch` —— **PHP 官方** backport（原样保存，附上游 commit）。
- `php-7.0.patch` ~ `php-7.3.patch`、`php-5.4.patch` ~ `php-5.6.patch` —— 本仓库依照官方修补逻辑移植到旧版本。

> 旧版本的移植补丁是**非官方**的，未经 PHP 官方审查，但每一版都在 Docker 中实际编译、并以 PHP 官方测试套件「修补前 vs 修补后」比对验证，确认没有破坏既有功能。每版的改动说明与验证数据见 `port-notes/`。

手动套用单个补丁：

```bash
cd php-7.3.33
patch -p1 < /path/to/php-7.3.patch
./configure ... && make && make install
```

---

## 目录结构

```
bt-php-security-update.sh   一键修复脚本（自带所有补丁，可直接下发到服务器）
patches/                    各版本独立补丁
src/                        脚本模板与构建器（build.sh 会把 patches/ 嵌入脚本）
port-notes/                 各旧版本移植的改动说明与验证数据
docs/                       漏洞与修补的技术说明
```

## 状态

本仓库正在完善中，各旧版本补丁陆续加入。当前进度以 `patches/` 下实际存在的文件为准。
