<div align="center">

# PHP 安全更新

**一行指令修補 PHP 嚴重 RCE 漏洞（CVE-2026-109618 / CVE-2026-109619）。** 自動偵測伺服器上所有 PHP——寶塔/aaPanel、原始碼編譯、系統套件——各自用正確的方式修補，並為官方從未修補的 EOL 版本提供原始碼級移植修補。

[English](README.md) · [繁體中文](README.zh-TW.md) · [简体中文](README.zh-CN.md) · [日本語](README.ja.md)

![PHP 5.4–8.5](https://img.shields.io/badge/PHP-5.4%20%E2%80%93%208.5-777BB4?style=flat-square&logo=php&logoColor=white)
[![Advisory](https://img.shields.io/badge/advisory-2026--10--21-red?style=flat-square)](https://www.php.net/archive/2026.php#2026-10-21-5)

</div>

## 漏洞說明

2026-10-21，PHP 官方公布兩個評分 CVSS 9.2 的嚴重漏洞，**未經身分驗證即可遠端執行程式碼（RCE）**，影響所有對外提供服務的 PHP（PHP-FPM、Apache mod_php、php-cgi、FrankenPHP、LiteSpeed）。

- 官方公告：<https://www.php.net/archive/2026.php#2026-10-21-5>
- `CVE-2026-109618`（GHSA-w8hw-w9fx-j79w）：記憶體不足時 PHP 以 `longjmp` 跳出半初始化的請求，關閉流程隨後處理到無效狀態。
- `CVE-2026-109619`（GHSA-6wmf-4rv5-p3rp）：上一個請求的內部狀態殘留到下一個請求，並在正常初始化前被讀取（釋放後使用）。

**唯一徹底的解法是升級到已修補的 PHP 版本。** 本倉庫一行指令完成，並為沒有官方 backport 的舊版本提供原始碼級修補。

## 一鍵修補

在伺服器上以 root 執行：

```bash
curl -fsSL https://raw.githubusercontent.com/lizhipay/php/main/php-security-update.sh -o php-security-update.sh && bash php-security-update.sh
```

腳本會**自動偵測這台伺服器上所有 PHP 安裝**——不限寶塔——並依來源與版本分別處理：

| 來源 | 處理方式 |
|---|---|
| 寶塔 / aaPanel（`/www/server/php/*`） | 自動重編並修補 |
| 原始碼編譯安裝（`/usr/local`、`/opt`、LiteSpeed lsphp、PATH 上的 php-fpm） | 自動重編並修補 |
| 系統套件安裝（apt / yum 的 php-fpm） | **只提示**——請用套件管理工具更新（發行版已有修補），不自動重編 |

| 版本範圍 | 處理方式 |
|---|---|
| 8.2 / 8.3 / 8.4 / 8.5 | 升級到同系列最新的已修補版本 |
| 7.4 / 8.0 / 8.1 | 升級到該系列最後一版，套用 **PHP 官方** backport 後重編 |
| 7.0 / 7.1 / 7.2 / 7.3 | 套用**本倉庫移植**的原始碼修補後重編 |
| 5.4 / 5.5 / 5.6 | 套用**本倉庫移植**的原始碼修補後重編 |
| 5.2 / 5.3 及更舊 | 僅套用官方緩解設定 |

常用參數：

```bash
bash php-security-update.sh --check      # 只檢查，列出計畫，不做任何變更
bash php-security-update.sh --only 74,82 # 只處理指定版本（版本號或安裝代號）
bash php-security-update.sh -y           # 不倒數，立即開始
```

### 安全設計

- 每個版本編譯並通過檢查後**才替換**；替換前**完整備份**，啟動驗證失敗會**自動還原**——網站只在 FPM 重啟時中斷約 1~2 秒。
- 所有原始碼一律**校驗 SHA256**；修補檔內嵌在腳本裡並自我校驗。
- 沿用原本的編譯參數與編譯器，升級後擴充模組與原本一致。
- PHP-FPM 重啟：有服務管理器就用它，否則用 `SIGUSR2` 平滑重載；都不行時提示手動重啟（絕不亂猜）。
- 系統套件安裝的 PHP 一律不碰，只給出套件更新指令，符合官方建議。

## 原始碼修補

官方只為 7.4 / 8.0 / 8.1 提供了 backport；更舊的版本什麼都沒有。`patches/` 下保存了可獨立取用的修補檔：

- `php-7.4.patch`、`php-8.0.patch`、`php-8.1.patch` —— **PHP 官方** backport，原樣保存（附上游 commit）。
- `php-7.0.patch` … `php-7.3.patch`、`php-5.4.patch` … `php-5.6.patch` —— 本倉庫依照官方修補邏輯移植到舊版本。

> 舊版本的移植修補是**非官方**的，未經 PHP 官方審查，但每一版都在 Docker 中實際編譯，並以 PHP 官方測試套件「修補前 vs 修補後」比對驗證，確認沒有破壞既有功能。每版的改動說明與驗證數據見 `port-notes/`；跨版本一致性核對見 `port-notes/AUDIT-concat-guards.md`。

手動套用單一修補檔：

```bash
cd php-7.3.33
patch -p1 < /path/to/php-7.3.patch
./configure ... && make && make install
```

## 目錄結構

```
php-security-update.sh   一鍵修補腳本（自帶所有修補檔，可直接下發）
patches/                 各版本獨立修補檔（3 個官方 + 7 個移植）
src/                     腳本範本與建構器（build.sh 自動把 patches/ 嵌入腳本）
port-notes/              各舊版本的改動說明、驗證數據與跨版核對
docs/                    漏洞與修補的技術說明
```

修改修補檔或範本後重新建構腳本：

```bash
bash src/build.sh ./php-security-update.sh
```

## 適用範圍與免責聲明

僅適用於 Linux。原始碼重編需要伺服器能安裝編譯工具鏈並連網下載 PHP 原始碼（已校驗 SHA256）。舊版本（7.0-7.3、5.4-5.6）的修補為非官方移植，按原樣提供；正式環境請先用 `--check` 查看計畫、並在離峰時段執行（腳本帶自動備份與還原）。徹底的長久之計仍是將這些站台遷移到受官方支援的 PHP 版本。
