---
description: 使用 HIBP k-anonymity 为密码候选补充 sweet/zero/common/unknown 计数分桶；只发送 SHA-1 前五位。Usage /breach-check <wordlist> [--limit N] [--with-counts]
---

# /breach-check

```bash
tools/breach_checker.py recon/target.com/wordlists/candidate-pool.txt --limit 10000 --with-counts
```

## 输出语义

- `sweet`：1–1000 次，优先供 AI 审阅。
- `zero`：未命中；目标品牌候选仍可能高价值。
- `unknown`：API 失败，不得伪装成 0 或在默认路径消失。
- `common`：>1000；可用 `--max-count` 显式过滤。

排序先按 `sweet → zero → unknown → common`，同一桶内保留候选池输入顺序作为目标相关性信号，不再简单 count DESC。

输出：

- `<input>-ranked.txt`：HIBP 审阅序列，仍是候选池。
- `<input>-ranked-counts.tsv`：`bucket\tcount\tpassword`。

`--limit` 默认取候选池前 N 条；`--shuffle` 仅为显式抽样兼容，不是 Credential Lane 默认。HIBP 结果只做 enrichment，最终 live 输入仍由 AI 生成 `spray-shortlist.txt`。

查询只保留少量 in-flight prefix futures，避免大池一次创建全部任务；`--limit` 与
`--concurrent` 必须为正整数，count 上下界冲突会在网络请求前失败。
