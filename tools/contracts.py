#!/usr/bin/env python3
"""Shared cross-owner contracts (stage-two #9).

跨 owner 不变量集中声明。任何一方改契约，另一方 import 同一常量——编译期可见。
这是 validate↔queue 集成缺口（藏两轮才暴露）的根治：契约不再散落在各 owner
的私有副本里。零 import（纯常量），不引入新循环。
"""

from __future__ import annotations

# --- Queue ↔ Checkpoint：激活字段与版本 ------------------------------------
# 权威定义在 tools/action_queue.py（ACTIVATION_REQUIRED_CLAIM_FIELDS）；此处
# 收编为共享常量，owner 与消费方 import 同一份。tests 断言两边一致。

# --- validate ↔ queue：终态契约 --------------------------------------------
# validate.py 的 canonical finding 终态与 queue resolve 的允许状态必须使用
# 同一集合，否则 validate 归档后 queue 还能把动作复活。
VALIDATE_TERMINAL_FINDING_STATES = frozenset({
    "validated",
    "rejected",
    "duplicate",
})

# --- checkpoint ↔ queue：锁序 ----------------------------------------------
# 所有同时持有两把锁的路径必须按此顺序获取，防死锁。
CHECKPOINT_QUEUE_LOCK_ORDER = ("checkpoint_witness_lock", "queue_mutation_lock")

# --- ledger ↔ runner：红线事件 ---------------------------------------------
# evidence_ledger 归档为 blocked_redline 的事件结果（红线三道闸的第三道：
# post-hoc 重写），runner/validate 不得将其当 tested_clean 消费。
LEDGER_REDLINE_EVENTS = frozenset({
    "blocked_redline",
})
