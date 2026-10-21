# 跨版稽核：concat 整数溢出防护点

官方 7.4 修补在字符串 concat 的内联 VM handler 里，于 `len = op1_len + op2_len`
喂给 `zend_string_extend` / `zend_string_alloc` 之前加了溢出防护
（`op1_len > SIZE_MAX - op2_len` → `zend_mm_safe_error_ex`）。这拦的是
「长度相加回绕成小值 → 分配出过小缓冲 → memcpy 堆溢出」，而这是分配器自身的
整数溢出检查拦不到的（分配本身用回绕后的小 size 成功了）。

对 7.0~7.3 四个移植版，套用补丁后用脚本核对 `Zend/zend_vm_execute.h` 内
每个 concat 分配点是否都在前几行有对应防护：

| 版本 | concat 分配点 | 已防护 | 未防护 | 未防护的是什么 |
|------|--------------|--------|--------|----------------|
| 7.0  | 27 | 27 | 0 | 无（见下方说明，属良性 over-guard） |
| 7.1  | 27 |  9+9=18 | 9 | FAST_CONCAT flat slow-path（与上游 7.4 一致，故意不加） |
| 7.2  | 45 | 36 | 9 | FAST_CONCAT flat slow-path（同上） |
| 7.3  | 43 | 34 | 9 | FAST_CONCAT flat slow-path（同上） |

结论：

- **7.1 / 7.2 / 7.3** 三者各自独立得到相同形态——只留下 9 个 FAST_CONCAT
  flat slow-path 分配点不加防护，和官方 7.4 的取舍完全一致。无防护缺口。
- **7.0** 把这 9 个也一起加了防护（全部 27 个都防护）。这是 **良性 over-guard**：
  多出的检查只有在 `op1_len + op2_len` 逼近 `SIZE_MAX` 时才会触发，而那样的长度
  根本无法真正分配出来，所以对任何可用输入都不会触发、行为与上游一致，只是比
  上游更严格；它不会漏防护，只会多防护，没有安全风险。为避免改动一个已通过
  编译与 make test 的补丁带来风险，保留 7.0 现状并在此记录此差异。

> 7.1 曾在首版误删这组 VM 防护（只看到 C-API `concat_function` 有防护，漏了
> VM 专用 handler），复查时发现并补回，详见 `71.md` 的 Correction 一节。

核对方法：对每个版本把 `patches/php-<ver>.patch` 套到纯净发行版，扫描
`zend_vm_execute.h` 里 `zend_string_(extend|realloc|alloc)(... op1 + op2 ...)` 的
分配点，检查其前 4 行内是否出现 `> (SIZE_MAX|ZEND_SIZE_MAX|ZSTR_MAX_LEN) - *op2*`
防护表达式。
