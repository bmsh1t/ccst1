# Bug Bounty 框架改进方案 TODO

> 生成时间：2026-08-07  
> 基于项目审核结果的优先级改进清单

---

## 📊 综合评分：9.0/10

### 核心优势
- ✅ AI-Tools 职责分离：决策与执行解耦，可审计可重放
- ✅ 状态持久化：5层状态系统 + checkpoint 机制
- ✅ 红线规则：窄边界拦截，不过度保守
- ✅ Coverage Matrix：端点×漏洞类别可视化
- ✅ Target Case State：多角色验证黄金标准
- ✅ SQL 注入：共享 payload 矩阵 + WAF 自适应
- ✅ Browser MCP 集成：标准化证据收集
- ✅ 26个 Slash Commands：语义清晰，组合性强
- ✅ 知识库治理：57张卡 + 质量门
- ✅ Credential Attack Lane：分阶段安全执行

---

## 🎯 快速实施优先级

| 改进项 | 优先级 | 工作量 | ROI | 推荐顺序 |
|---|---|---|---|---|
| Credential Lane 硬性栅栏 | P0 | 3天 | ⭐⭐⭐⭐⭐ | **1** |
| 统一状态管理 Facade | P0 | 2周 | ⭐⭐⭐⭐☆ | **2** |
| MCP 失败自动降级 | P1 | 2天 | ⭐⭐⭐⭐☆ | **3** |
| 分布式锁支持 | P0 | 3天 | ⭐⭐⭐☆☆ | **4** |
| Coverage Matrix 智能提醒 | P1 | 5天 | ⭐⭐⭐⭐☆ | **5** |
| Lock 超时清理 | P2 | 0.5天 | ⭐⭐⭐☆☆ | **6** |
| 全局速率限制 | P2 | 1天 | ⭐⭐⭐☆☆ | **7** |
| 知识库相似度推荐 | P2 | 1周 | ⭐⭐☆☆☆ | **8** |

---

## P0 级改进（立即实施）

### 1️⃣ Credential Lane 硬性安全栅栏 ⭐⭐⭐⭐⭐

**工作量**：3天  
**优先级**：P0（最高）

#### 现状问题
- AI shortlist 质量依赖判断，无硬性限制
- 误判可能导致大规模 spray（如 1000账号 × 100密码 = 100万次尝试）
- 缺少"预算耗尽"自动停止机制

#### 改进方案
创建三层安全栅栏：

**栅栏1：输入验证（硬性限制）**
```python
HARD_LIMITS = {
    "max_users": 100,           # 最多100个账号
    "max_passwords": 20,        # 最多20个密码
    "max_attempts": 2000,       # 总尝试次数上限
    "max_rate_per_min": 10,     # 每分钟最多10次
}
```

**栅栏2：速率限制**
- 实时监控 attempts_last_minute
- 超限自动等待60秒

**栅栏3：自动停止条件**
- 命中1个有效凭据立即停止
- 预算耗尽停止（minimal/balanced/aggressive三档）
- 连续失败5次停止（防账号锁定）

#### 实施步骤
1. 创建 `tools/spray_guard.py`
2. 实现三层栅栏逻辑
3. 集成到 `/spray` 命令
4. 添加测试用例（正常/超限/误判场景）
5. 更新文档 `skills/credential-attack/SKILL.md`

#### 验收标准
- [ ] 硬性限制无法覆盖（除非 `--force-override` + 二次确认）
- [ ] 三档预算（minimal/balanced/aggressive）正常工作
- [ ] 命中1个凭据后立即停止
- [ ] 连续失败5次自动停止
- [ ] 所有尝试进入审计日志（`.private/spray_audit.jsonl`）

---

### 2️⃣ 统一状态管理 Facade ⭐⭐⭐⭐☆

**工作量**：2周（1周开发 + 1周重构迁移）  
**优先级**：P0

#### 现状问题
- 5个独立状态系统（Checkpoint、Action Queue、Observation Inventory、Evidence Ledger、Finding Index）
- AI 需要调用5个不同 API，顺序写入要求高
- 一致性维护复杂，容易遗漏刷新

#### 改进方案
创建 `StateManager` Facade，统一状态读写接口

**核心API**：
```python
class StateManager:
    def __init__(self, repo_root: Path, target: str)
    
    def transaction(self, systems: list[str]) -> ContextManager
    def load_state(self, system: str) -> dict
    def update_state(self, system: str, updates: dict) -> None
    def get_unified_projection(self) -> dict  # 替代 autopilot_state.py
```

**使用对比**：
```python
# ❌ 原来：手动调用5个 API + 手动加锁
with checkpoint_witness_lock(...):
    with queue_mutation_lock(...):
        checkpoint = load_checkpoint(...)
        queue = load_queue(...)
        checkpoint["phase"] = "hunting"
        save_checkpoint(...)
        queue["actions"].append(...)
        save_queue(...)

# ✅ 现在：一个事务搞定
with manager.transaction(systems=["checkpoint", "queue"]):
    manager.update_state("checkpoint", {"phase": "hunting"})
    manager.update_state("queue", {"actions": [...]})
    # 自动保存，自动刷新
```

#### 实施步骤
1. 创建 `tools/state_manager.py`（核心 Facade）
2. 实现 `transaction()` 上下文管理器（自动加锁/保存）
3. 实现 `get_unified_projection()`（替代 `autopilot_state.py` 聚合逻辑）
4. 添加缓存层（减少重复读取）
5. 重构现有调用点（约50+处）：
   - `commands/autopilot.md` 实现
   - `tools/checkpoint.py` 调用处
   - `tools/hunt.py` 状态写入
6. 添加集成测试（并发、锁竞争、事务回滚）
7. 更新文档

#### 验收标准
- [ ] 所有状态读写通过 `StateManager`
- [ ] 事务性保证（要么全成功，要么全失败）
- [ ] 自动锁管理（无需手动加锁）
- [ ] 减少80%的状态管理代码
- [ ] 通过并发压力测试（10个并发 autopilot）

---

### 3️⃣ MCP 失败自动降级策略 ⭐⭐⭐⭐☆

**工作量**：2天  
**优先级**：P1

#### 现状问题
- Browser MCP 失败后 checkpoint blocker，需手动修复
- 无人值守 `/autopilot` 可能卡住
- 缺少 fallback 策略

#### 改进方案
三级降级策略：
1. **mcp_live**（最优）：实时 Playwright/Chrome DevTools MCP
2. **mcp_cached**（次优）：使用缓存的 browser 证据
3. **js_source**（保守）：从 JS/Source 推断路由
4. **skip**（兜底）：标记为 blocked，不中断 autopilot

**自动降级流程**：
```
mcp_live 失败 → 重试1次 → 失败
   ↓
mcp_cached（使用缓存）→ 无缓存
   ↓
js_source（从 JS 推断）→ 无 JS
   ↓
skip（标记 blocked，继续其他 lane）
```

#### 实施步骤
1. 创建 `tools/browser_fallback.py`
2. 实现 `BrowserStrategy` 类（三级降级）
3. 集成到 `/autopilot` 的 browser 阶段
4. 添加透明度日志（明确告知使用了哪种策略）
5. 测试场景：
   - MCP 不可用
   - MCP 超时
   - 缓存过期
   - 无 JS 可推断

#### 验收标准
- [ ] MCP 失败不中断 `/autopilot`
- [ ] 自动尝试3级策略
- [ ] 透明度：明确输出使用了哪种策略
- [ ] 缓存证据有时效性标注（age_hours）
- [ ] JS 推断至少覆盖 React Router/Vue Router/Express 路由

---

### 4️⃣ 分布式锁支持（多机器协作）⭐⭐⭐☆☆

**工作量**：3天  
**优先级**：P0（团队协作场景必需）

#### 现状问题
- 仅本地 `fcntl` 锁，多机器并发测试同一目标会冲突
- 团队协作场景无法并行（如 Alice 测 SQLi，Bob 测 IDOR）

#### 改进方案
支持 Redis 分布式锁（可选，fallback 到本地锁）

**架构**：
```python
# 统一接口
with distributed_lock("example.com:sqli", backend="redis"):
    test_sqli("example.com")

# 自动 fallback
# Redis 可用 → RedisLockBackend
# Redis 不可用 → LocalLockBackend（fcntl）
```

**特性**：
- 自动超时释放（防进程崩溃后锁残留）
- Per-lane 锁（SQLi 和 IDOR 可并行）
- Graceful fallback（Redis 不可用时自动降级）

#### 实施步骤
1. 创建 `tools/distributed_lock.py`
2. 实现 `RedisLockBackend`（使用 `redis-py`）
3. 实现 `LocalLockBackend`（现有 fcntl 逻辑）
4. 实现 `distributed_lock()` 上下文管理器
5. 集成到 `StateManager.transaction()`
6. 添加配置项（`.env` 中的 `REDIS_URL`）
7. 测试场景：
   - 两台机器同时测试同一目标不同 lane
   - Redis 宕机时自动 fallback
   - 进程崩溃后锁自动释放（300秒超时）

#### 验收标准
- [ ] 支持 Redis 分布式锁
- [ ] Redis 不可用时自动 fallback 到本地锁
- [ ] 锁超时自动释放（默认300秒）
- [ ] Per-lane 粒度（不同 lane 可并行）
- [ ] 通过多机器并发测试

---

## P1 级改进（1-2周内）

### 5️⃣ Coverage Matrix 智能提醒 ⭐⭐⭐⭐☆

**工作量**：5天  
**优先级**：P1

#### 现状问题
- 高价值 surface 列表（登录/SSO/上传/webhook）是文档性的
- AI 可能遗漏关键表面
- 缺少"这个端点应该测哪些类别"的智能提示

#### 改进方案
基于启发式规则 + 历史数据的智能提醒系统

**启发式规则**：
```python
HEURISTIC_RULES = [
    (r"/login|/signin|/auth", ["csrf", "brute_force", "session"]),
    (r"/api/users/\{?\w+\}?", ["idor", "mass_assignment", "priv_esc"]),
    (r"/upload|/import", ["file_upload", "xxe", "ssrf"]),
    (r"/webhook|/callback", ["ssrf", "open_redirect"]),
    # ... 30+ 规则
]
```

**历史学习**：
- 查找相似端点（特征向量相似度）
- 聚合历史发现（"相似端点曾发现 IDOR"）
- 优先级排序（高价值端点 × 高影响漏洞）

**输出示例**：
```
📊 Coverage Gaps with AI Hints:

/api/users/{id}
  🎯 Priority 85: idor
     Reason: Pattern match; Similar endpoint /api/accounts/123 had idor (similarity: 80%)
  🎯 Priority 70: mass_assignment
     Reason: Pattern match
```

#### 实施步骤
1. 创建 `tools/coverage_hints.py`
2. 实现 `CoverageHintEngine` 类
3. 添加30+启发式规则
4. 实现相似度计算（特征向量 + 余弦相似度）
5. 集成到 `coverage_matrix.py find-gaps --with-hints`
6. 添加历史数据库（`memory/pattern_db.py`）

#### 验收标准
- [ ] 30+ 启发式规则覆盖常见端点类型
- [ ] 相似度计算准确率 >70%
- [ ] 优先级排序合理（手动验证10个案例）
- [ ] `find-gaps --with-hints` 输出清晰可读

---

### 6️⃣ Lock 超时自动清理 ⭐⭐⭐☆☆

**工作量**：0.5天  
**优先级**：P2

#### 改进方案
创建 lock janitor，自动清理过期锁文件

```python
# tools/lock_janitor.py
def cleanup_stale_locks(lock_dir: Path, max_age_seconds: int = 3600):
    """清理超过1小时的锁文件"""
    now = time.time()
    for lock_file in lock_dir.glob("*.lock"):
        age = now - lock_file.stat().st_mtime
        if age > max_age_seconds:
            print(f"🧹 Cleaning stale lock: {lock_file.name}")
            lock_file.unlink()
```

**部署方式**：
```bash
# Cron job（每10分钟）
*/10 * * * * cd /path/to/repo && python3 tools/lock_janitor.py
```

#### 实施步骤
1. 创建 `tools/lock_janitor.py`
2. 添加 CLI 参数（`--max-age`, `--dry-run`）
3. 添加到项目 README 的"维护任务"章节
4. 可选：集成到 `/autopilot` 启动时自动运行

#### 验收标准
- [ ] 正确清理超过1小时的锁文件
- [ ] 不误删活跃锁
- [ ] `--dry-run` 模式可预览

---

## P2 级改进（1个月内）

### 7️⃣ 全局速率限制器 ⭐⭐⭐☆☆

**工作量**：1天  
**优先级**：P2

#### 改进方案
```python
# tools/global_rate_limiter.py
class GlobalRateLimiter:
    """全局请求速率限制（跨所有 lane）"""
    def __init__(self, max_per_second: int = 100):
        ...

# 统一HTTP请求入口
def rate_limited_request(url: str, **kwargs):
    _GLOBAL_LIMITER.acquire()
    return requests.request(url, **kwargs)
```

#### 实施步骤
1. 创建 `tools/global_rate_limiter.py`
2. 实现滑动窗口算法
3. 替换所有 `requests.request()` 为 `rate_limited_request()`
4. 添加配置项（`config.json` 中的 `global_rate_limit`）

#### 验收标准
- [ ] 全局速率限制生效（100 req/s）
- [ ] 多 lane 并发时不超限
- [ ] 可配置限制值

---

### 8️⃣ 知识库相似度推荐 ⭐⭐☆☆☆

**工作量**：1周  
**优先级**：P2

#### 改进方案
基于目标特征（技术栈、端点类型、历史发现）自动推荐知识卡

```python
# tools/knowledge_recommender.py
class KnowledgeRecommender:
    def recommend(self, target: str, current_evidence: Dict) -> List[str]:
        # 1. 提取目标特征向量
        # 2. 计算与历史目标的相似度
        # 3. 聚合相似目标使用过的知识卡
        # 4. 按effectiveness排序
        ...
```

**使用示例**：
```bash
/context-pack web2-vuln-classes --auto-recommend

# 输出：
# 🤖 AI推荐知识卡（基于相似目标）:
#   1. knowledge/cards/graphql.md (score: 0.85)
#      Reason: Similar target api.example.com (similarity: 92%)
#   2. knowledge/cards/api-idor.md (score: 0.78)
```

#### 实施步骤
1. 创建 `tools/knowledge_recommender.py`
2. 实现特征提取（技术栈、端点类型等）
3. 实现相似度计算（余弦相似度）
4. 集成到 `/context-pack --auto-recommend`
5. 记录知识卡effectiveness（成功发现/总使用次数）

#### 验收标准
- [ ] 相似度计算准确
- [ ] 推荐Top 3知识卡
- [ ] effectiveness 统计准确

---

## 📅 实施时间表

### 第一阶段（第1周）
- **Day 1-3**：Credential Lane 硬性栅栏 ✅ P0
- **Day 4-5**：MCP 失败自动降级 ✅ P1
- **Day 5**：Lock 超时清理 ✅ P2

### 第二阶段（第2-3周）
- **Week 2**：Coverage Matrix 智能提醒（5天）✅ P1
- **Week 2-3**：统一状态管理 Facade（2周）✅ P0
- **Week 3**：分布式锁支持（3天）✅ P0

### 第三阶段（第4周）
- **Day 1**：全局速率限制 ✅ P2
- **Week 4**：知识库相似度推荐（1周）✅ P2

---

## 📝 维护检查清单

### 每日
- [ ] 运行 `pytest` 确保测试通过
- [ ] 检查 `/memory-gc` 日志大小

### 每周
- [ ] 运行 `/sync-check` 检查 runtime drift
- [ ] 运行 `python3 tools/knowledge_audit.py --strict`
- [ ] 检查 `.private/` 目录大小（必要时备份）

### 每月
- [ ] 运行 `git diff --check` 检查代码规范
- [ ] 更新 `CHANGELOG.md`
- [ ] 清理旧的 checkpoint 文件（>30天）

---

## 🎓 团队培训建议

### 新成员上手（3天）
- **Day 1**：阅读 `CLAUDE.md` + `rules/hunting.md` + `rules/red-lines.md`
- **Day 2**：练习 `/recon` → `/surface` → `/hunt` 工作流（CTF目标）
- **Day 3**：练习 `/autopilot` 深度模式 + Target Case State

### 进阶培训（1周）
- 知识库体系（57张卡的使用时机）
- 自定义 validation_runner lane
- 编写新的知识卡（按 `capabilities.yaml` 规范）

---

## 🔗 相关文档

- 审核报告：`docs/audit-report-2026-08-07.md`（本次审核的详细版）
- 架构图：`docs/architecture-diagram.md`（待补充）
- API 文档：`docs/api-reference.md`（待补充）
- 贡献指南：`CONTRIBUTING.md`（待补充）

---

**最后更新**：2026-08-07  
**维护者**：@lexandersaw  
**状态**：初始版本
