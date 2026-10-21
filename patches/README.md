# patches

每个文件是针对对应 PHP 版本源码的统一 diff，用 `patch -p1` 套用到官方发行版解压后的源码树。

- `php-7.4.patch` / `php-8.0.patch` / `php-8.1.patch`：PHP 官方 backport，原样保存。
  对应上游 commit：
  - 7.4 → `712e60f9edfd03f0960fc4fc3c2c375f42b90aa2`
  - 8.0 → `82f8f31b16a035c1b67cc253e79f7cc288f4cc20`
  - 8.1 → `1d7dec178a094e6e75b229ce22754045f8c6070a`
- 其余版本为本仓库移植，非官方，改动说明见 `../port-notes/`。
