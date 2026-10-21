# session 物件注入硬化補丁（opt-in）

這裡的補丁處理的是**另一個**問題，跟本次 CVE-2026-109618 / 109619 無關，官方那次的修補也不會修到它：

**`session.serialize_handler` 混用造成的物件注入**。寫入側用 `php_serialize`、讀取側用 `php`（可能來自不同 vhost / pool / `.user.ini` 的設定），`php` 解碼器在第一個 `|` 切 `key|value`，於是把攻擊者透過 `PHP_SESSION_UPLOAD_PROGRESS` 塞進 session key 的 `|O:...` 當成序列化值 `unserialize`，再靠 POP chain 的 `__wakeup`/`__destruct` 執行程式碼（未經身分驗證）。

## 補丁做什麼

新增一個 ini 旗標 **`session.harden`**（bool、預設 `0`、`PHP_INI_SYSTEM`）。預設關閉時，打過補丁的 PHP 跟原版行為完全相同，所以把物件存進 session 的應用不受影響，直到管理者主動開啟。

`session.harden = 1` 時：

1. **所有 session 解碼器拒絕物件**：每次 session 反序列化都給一個空的 allowed-classes 集合，session 資料裡的 `O:`/`C:` 一律變成 `__PHP_Incomplete_Class`——不自動載入、不呼叫 `__wakeup`/`__unserialize`/`__destruct`，POP chain 失效。不論資料是哪個 handler 寫的都擋得住。
2. **淨化 upload_progress key**：把存入 key 的攻擊者值裡的 `|`、`!`（`php` / `php_binary` 的分隔符）換成 `_`，封住未經驗證的投遞向量。

一鍵腳本用 `--harden` 套用：重編打上這個補丁、在 php.ini 開 `session.harden=1`，並一併設定 `session.upload_progress.enabled=0`、`session.use_strict_mode=1`、`session.use_only_cookies=1`。即使該 PHP 已是最新修補版，`--harden` 也會為它重編一次以打上本補丁。

## 版本覆蓋

| 版本 | object-deny | upload_progress 淨化 | 機制 |
|---|---|---|---|
| 8.2 – 8.5 | ✅ | ✅ | `php_var_unserialize_set_allowed_classes`（空表） |
| 7.1 – 8.1 | ✅ | ✅ | 同上（每個解碼器各自設定） |
| 7.0 | ✅ | ✅ | `php_var_unserialize_ex(..., 空表)`（7.0 無 setter） |
| 5.4 – 5.6 | ❌ N/A | ✅ | 5.x 的 `php_var_unserialize` 沒有 classes 參數，C 層無法做 object-deny |

> **5.x 限制**：本補丁在 5.4–5.6 只封住 upload_progress 投遞向量，**擋不住** serialize_handler 混用的物件注入 RCE。5.x 上該風險只能靠設定層防禦：session 不要存物件、全站固定單一 `session.serialize_handler`、移除各處覆寫。長久之計是遷移到受官方支援的版本。

## 驗證

每個版本都在 Docker 實際編譯，並以注入測試（`harden=0` 應觸發、`harden=1` 應擋下）確認；7.0+ 全部 `harden=1` 擋下，5.x 以真實 multipart 上傳確認 `|`/`!` 被淨化。預設關閉時與原版零行為差異。各版細節見 `notes/`。

## 手動套用

```bash
cd php-8.2.35
patch -p1 < /path/to/hardening/php-8.2-session-hardening.patch
./configure ... && make && make install
# 然後在 php.ini 設 session.harden = 1
```
