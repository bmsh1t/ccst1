---
description: 生成目标相关的凭据候选池；cewler 原词、Hashcat 规则和品牌 pydictor 变异分层落盘，不执行 Spray。Usage /wordlist-gen <target> [--mode minimal|balanced|aggressive]
---

# /wordlist-gen

生成供 AI 审阅的候选池，不生成可直接 live 的密码清单。

```bash
tools/wordlist_engine.sh target.com --filter strict --mode balanced
```

## 数据流

1. cewler → `from-website.txt`。
2. 稳定去重和长度过滤 → `cleaned.txt`。
3. Hashcat 对 cleaned 原词批量变异 → `website-hashcat.txt`。
4. pydictor 只扩展域名品牌词 → `brand-pydictor.txt`。
5. 按“品牌定向 → cleaned 原词 → Hashcat 变异”稳定 exact 去重 → `candidate-pool.txt`。

`ranked.txt` 是兼容 alias，含义同 candidate pool；不得直接交给 live `/spray`。

## 模式

| 模式 | Hashcat rule | 用途 |
|---|---|---|
| minimal | `top10_2025.rule` | 小型候选池 |
| balanced | `best66.rule` | 默认 |
| aggressive | `OneRuleToRuleThemStill.rule` | 仅离线候选准备 |

工具发现顺序：显式环境变量 → `$PATH` → `$HOME/Tools`。单个来源缺失时保留其他来源；所有来源均为空才失败。不自动安装工具。

下一步：`/breach-check candidate-pool.txt --with-counts`，再由 AI 结合目标证据生成有限的 `spray-shortlist.txt`。
