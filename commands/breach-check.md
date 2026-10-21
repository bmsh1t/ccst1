---
description: 使用 HIBP k-anonymity 补充密码候选计数，保留输入顺序和 unknown；只发送 SHA-1 前五位。Usage /breach-check <wordlist> [--limit N] [--with-counts]
---

# /breach-check

```bash
tools/breach_checker.py recon/target.com/wordlists/candidate-pool.txt --limit 10000 --with-counts
```

## 输出语义

- `sweet`：1–1000 次，保留旧标签兼容；不表示优先级。
- `zero`：成功且格式合法的 range 查询未返回该候选的正计数；不证明安全或目标相关性。
- `unknown`：计数为 `-1`；包括 429 重试耗尽、传输失败、空或损坏响应。不得伪装成 0 或被 count 过滤丢弃。
- `common`：>1000；可用 `--max-count` 显式过滤。

输出保留稳定去重后的候选输入顺序，不按 bucket 或泄露计数排序，也不把输入顺序解释为目标相关性。
`--min-count` / `--max-count` 只过滤已知计数；未知项始终保留。

输出：

- `<input>-ranked.txt`：兼容文件名，内容是按输入顺序保留的候选池。
- `<input>-ranked-counts.tsv`：使用 `--with-counts` 时写入 `bucket\tcount\tpassword`，行序与输出候选一致。

完整查询返回 `0`；存在未知计数时仍写出结果，摘要标为 `partial` 并返回 `2`。
stderr 汇总失败类型与 prefix 数量，不输出候选明文或 SHA-1 prefix。参数错误也返回 `2`，但发生在查询前。

`--limit` 默认取候选池前 N 条；显式 `--shuffle` 在 `--limit` 前打乱输入，后续仍保留该顺序，`--seed` 可复现抽样。HIBP 结果只做 enrichment，最终 live 输入仍由 AI 生成 `spray-shortlist.txt`。

查询只保留少量 in-flight prefix futures，避免大池一次创建全部任务；`--limit` 与
`--concurrent` 必须为正整数，count 上下界冲突会在网络请求前失败。
