# Claude Bug Bounty 项目最优方案 - AI能力解放计划

## 项目信息
- **项目名称**: Claude Bug Bounty (AI-Driven Security Testing Platform)
- **当前版本**: v4.4.1
- **当前评分**: 9.1/10 (架构优秀，但限制了AI能力)
- **目标评分**: 9.5/10 (架构优秀 + AI能力完全释放)
- **开始日期**: 2026-09-11
- **预计周期**: 4-6 周

## Goal

**不是重构架构，而是解放 AI 能力。**

基于项目核心哲学："解放 AI 的思考能力，约束 AI 的行为边界"，移除当前限制 AI 能力发挥的 7 个关键障碍，同时保持已验证优秀的架构设计。

**成功标准：**
1. AI 决策速度提升 3-5x（减少中间层开销）
2. AI 测试覆盖深度提升 40-60%（移除人为限制）
3. 跨目标学习效果提升 50%（智能 Pattern Matching）
4. 保持所有测试通过（3,457 passed）
5. 修复当前的 17 个测试失败

## Current Phase

**Phase 0: 修复当前问题** (Status: **not_started**)

## Next Step

启动 Phase 0：修复 17 个测试失败和安装层漂移（预计 3-5 天）

---

## 核心理念

### ✅ 保留的优秀设计（不动）
1. **五平面架构** - 清晰且落地 (9.5/10)
2. **状态 Owner 机制** - 8/8 完美验证，带锁和原子写
3. **Autopilot 引擎** - 世界级 (9.17/10)，独创的 Loop Guard、Global Review
4. **记忆系统** - JSONL 格式完美，跨目标学习有价值
5. **测试覆盖** - 3,474 个测试
6. **MCP 集成** - Burp/Caido/HackerOne

### 🎯 要解决的核心问题
**不是架构问题，是 AI 能力限制问题：**
1. 过度的上下文门控（Context Pack 中间层）
2. Tool/AI Boundary 矛盾（"这是建议" vs "你要自己判断"）
3. Scanner 能力刻意削弱（AI 不擅长穷举）
4. 固定的 Skill Dimensions（强制 7 维度）
5. Coverage Matrix 的心智负担（50 个 untested 单元格）
6. 知识碎片化（8000+ 行分散在 40+ 文件，只推荐 2 张卡）
7. 时间限制过严（30s/5min 可能错过深层漏洞）

---

## Phases

### Phase 0: 修复当前问题
**Status:** not_started  
**Duration:** 3-5 天  
**Priority:** P0 - CRITICAL

**目标：** 将项目恢复到可用状态

**当前问题（来自最新审核）：**
- ❌ 17 个测试失败（8 个文档契约 + 4 个安装层 + 5 个环境）
- ❌ 安装层 critical drift = 3（会阻塞 `/autopilot` 启动）
- ❌ README 4 处漂移

**Tasks:**
1. **修复 8 个文档契约测试** (1-2 天)
   - 恢复 web2-vuln-classes 的 A/B 锚点词
   - 修复 autopilot.md 的契约断言
   - 修复 tool-index.md 行长度
   
2. **同步安装层** (1 天)
   - 运行 `/sync-check --sync`
   - 验证 autopilot 启动正常
   
3. **修复环境依赖** (1 天)
   - 添加 badsecrets skip 保护
   - 移除硬编码路径依赖
   
4. **更新 README** (半天)
   - 修正测试徽章
   - Python 3.8+ → 3.10+
   - 15 → 19 classes
   - 标注已退役的 LoopDetector

5. **提交 tests/__init__.py** (立即)

**Expected Outcome:**
- ✅ 所有测试通过（3,474 passed, 0 failed）
- ✅ `/autopilot` 可正常启动
- ✅ README 准确反映现状

---

### Phase 1: 移除上下文门控，让 AI 直接访问
**Status:** not_started  
**Duration:** 1 周  
**Priority:** HIGH

**目标：** 废除 Context Pack 中间层，AI 直接读取状态

**问题分析：**
```text
当前：
  AI → Context Pack (3552 lines)
      → 推荐 0-2 张卡
      → 过滤上下文
      → AI 看到被裁剪的视图

改进后：
  AI → 直接读取 state.json + 智能索引
      → 按需加载知识卡（无固定限制）
      → AI 看到完整视图，自己判断
```

**Tasks:**

1. **创建智能知识索引** (2-3 天)
   ```python
   # tools/knowledge_index.py (NEW)
   class KnowledgeIndex:
       """智能知识卡片索引"""
       
       def search(self, query: str, top_k: int = 10):
           """关键词搜索知识卡片"""
           # 返回匹配的卡片列表和摘要
       
       def get_related(self, card_name: str):
           """获取关联卡片"""
           # 返回相关卡片的摘要
       
       def load_card(self, card_name: str):
           """完整加载单张卡片"""
   ```

2. **简化状态访问** (1-2 天)
   ```python
   # tools/simple_state.py (NEW)
   class SimpleState:
       """简化的状态访问接口"""
       
       def get_context(self, target: str):
           """返回完整上下文，不过滤"""
           return {
               "target": target,
               "goal": ...,
               "tested": ...,
               "findings": ...,
               "knowledge_index": KnowledgeIndex(),  # AI 自己搜索
           }
   ```

3. **更新 CLAUDE.md** (1 天)
   ```markdown
   # 新的指导原则
   
   ## 知识获取
   - 使用 knowledge_index.search("ssrf") 搜索相关卡片
   - 阅读摘要，决定是否完整加载
   - 无固定卡片数量限制
   
   ## 状态访问
   - 直接读取 state.json
   - 不需要通过 Context Pack
   ```

4. **废弃 Context Pack** (1 天)
   - 保留代码（向后兼容）
   - 更新文档标记为 deprecated
   - 新流程不再使用

**Expected Outcome:**
- ✅ AI 可以自由搜索和加载知识卡片
- ✅ 移除 "0-2 张卡" 的人为限制
- ✅ 减少上下文加载时间 50%

---

### Phase 2: 工具信任分级，消除 Advisory 矛盾
**Status:** not_started  
**Duration:** 1 周  
**Priority:** HIGH

**目标：** 明确工具输出的置信度，让 AI 知道哪些可以信任

**问题分析：**
```text
当前矛盾：
  Scanner: "这个端点 tested_clean"
  System: "但这只是 advisory，你要自己判断"
  AI: "那我重新测试..." [浪费 tokens]

改进后：
  Scanner: "tested_clean, confidence=HIGH (Nuclei CVE-2023-1234 匹配)"
  AI: "HIGH 置信度，我直接采信" [节省 tokens]
  
  Scanner: "possible IDOR, confidence=MEDIUM (参数模式匹配)"
  AI: "MEDIUM 置信度，我快速验证 2-3 个案例"
```

**实现三档信任模型：**

```python
# tools/confidence.py (NEW)

class ToolConfidence(str, Enum):
    HIGH = "high"      # AI 可以直接采信
    MEDIUM = "medium"  # AI 快速验证 (1-2 min)
    LOW = "low"        # AI 深度验证 (5-10 min)

class ConfidenceRules:
    """置信度判断规则"""
    
    @staticmethod
    def assess_scanner_result(result: dict) -> ToolConfidence:
        """评估 Scanner 结果的置信度"""
        
        # HIGH: 确定性检查
        if result.get("matcher") == "cve_template":
            return ToolConfidence.HIGH
        
        if result.get("evidence") == "error_with_stacktrace":
            return ToolConfidence.HIGH
        
        # MEDIUM: 启发式检测
        if result.get("matcher") == "parameter_pattern":
            return ToolConfidence.MEDIUM
        
        if result.get("evidence") == "status_code_anomaly":
            return ToolConfidence.MEDIUM
        
        # LOW: 模糊匹配
        return ToolConfidence.LOW
```

**Tasks:**

1. **更新 vuln_scanner.sh** (2 天)
   - 为每个发现添加 confidence 字段
   - CVE 匹配 → HIGH
   - 参数模式 → MEDIUM
   - 通用检测 → LOW

2. **更新 validate.py** (1 天)
   - 读取 confidence 字段
   - HIGH: 快速验证（30s）
   - MEDIUM: 标准验证（5 min）
   - LOW: 深度验证（15 min）

3. **更新 CLAUDE.md** (1 天)
   ```markdown
   ## 工具输出信任级别
   
   - **HIGH confidence**: 可以直接采信
     - Nuclei CVE 模板匹配
     - 明确的错误堆栈
     
   - **MEDIUM confidence**: 快速验证即可
     - 参数模式匹配
     - 状态码异常
     
   - **LOW confidence**: 需要深度验证
     - 通用模糊匹配
     - 弱信号
   ```

4. **创建置信度文档** (1 天)
   - `docs/tool-confidence-guide.md`
   - 列出所有工具的置信度规则

**Expected Outcome:**
- ✅ 减少 50-70% 的重复验证工作
- ✅ AI 明确知道哪些结果可以信任
- ✅ 加快整体测试速度

---

### Phase 3: 增强 Scanner，让它做它擅长的事
**Status:** not_started  
**Duration:** 1 周  
**Priority:** MEDIUM

**目标：** Scanner 负责穷举，AI 负责推理

**问题分析：**
```text
当前设计：
  Scanner: "这里可能有 SQLi 注入点"
  AI: "让我构造 10000 个 payload 测试..." [不擅长]

改进后：
  Scanner: "我已经测试了 10000 个 SQLi payload，发现 5 个可疑点"
  AI: "我验证这 5 个可疑点" [擅长]
```

**混合模式设计：**

```bash
# tools/vuln_scanner.sh (增强)

# Scanner 负责：
1. 确定性检查（CVE、配置错误）
2. 穷举式探测（参数发现、编码边界）
3. 大规模 payload 扫描（常见 SQLi/XSS pattern）

# AI 负责：
1. 业务逻辑漏洞
2. 复杂的攻击链构造
3. 深度语义分析
4. 根据响应动态调整策略
```

**Tasks:**

1. **恢复 Scanner payload 测试** (2-3 天)
   ```bash
   # vuln_scanner.sh (增强)
   
   # SQLi 穷举测试
   run_sqli_scan() {
       for payload in "${SQLI_PAYLOADS[@]}"; do
           test_endpoint "$endpoint" "$payload"
       done
       # 返回可疑响应（confidence=MEDIUM）
   }
   
   # XSS 穷举测试
   run_xss_scan() {
       for payload in "${XSS_PAYLOADS[@]}"; do
           test_endpoint "$endpoint" "$payload"
       done
   }
   ```

2. **添加边界字符探测** (1 天)
   ```bash
   # 测试各种编码和边界字符
   BOUNDARY_CHARS=("'" '"' ";" "|" "&" "<" ">" "{" "}" "[" "]")
   
   for char in "${BOUNDARY_CHARS[@]}"; do
       response=$(test_char "$endpoint" "$char")
       analyze_response "$response"
   done
   ```

3. **保持 AI 决策权** (1 天)
   - Scanner 结果标记为 confidence=MEDIUM
   - AI 决定是否深入验证
   - AI 可以覆盖 Scanner 结论

4. **更新文档** (1 天)
   ```markdown
   # tools/tool-ai-boundary.md (更新)
   
   ## Scanner 职责
   - 穷举式测试（AI 不擅长）
   - 确定性检查（可信度高）
   - 大规模覆盖（节省 AI tokens）
   
   ## AI 职责
   - 业务逻辑分析（Scanner 不擅长）
   - 攻击链构造（需要推理）
   - 动态策略调整（需要判断）
   ```

**Expected Outcome:**
- ✅ Scanner 负责穷举，AI 负责推理
- ✅ 提升测试覆盖率 40-60%
- ✅ 减少 AI 在重复工作上的 token 消耗

---

### Phase 4: 移除固定维度，让 AI 自由思考
**Status:** not_started  
**Duration:** 3-5 天  
**Priority:** MEDIUM

**目标：** 废除强制的 7 维度要求

**问题分析：**
```python
# 当前：强制 7 个维度
SKILL_CATALOG = {
    "required_dimensions": [
        "vulnerability_family",  # 强制
        "parameter",             # 强制
        "encoding",              # 强制
        "auth",                  # 强制
        "sibling",               # 强制
        "workflow",              # 强制
        "chain",                 # 强制
    ],
}

# 问题：新的攻击角度可能不在这 7 个维度中
# 例如："CDN 缓存和后端逻辑的时间差"
#   - vulnerability_family: ??? (不是传统类别)
#   - parameter: ??? (不是参数级别)
#   - encoding: ??? (跟编码无关)
```

**Tasks:**

1. **改为建议维度** (1 天)
   ```python
   # tools/skill_catalog.py (修改)
   
   SKILL_CATALOG = {
       "suggested_dimensions": [  # 改为建议
           "vulnerability_family",
           "parameter",
           "encoding",
           "auth",
           "sibling",
           "workflow",
           "chain",
       ],
       "required_minimum": 3,  # 至少覆盖 3 个即可
       "allow_custom": True,   # 允许自定义维度
   }
   ```

2. **支持自定义维度** (1-2 天)
   ```python
   class SkillAnalysis:
       def validate(self, analysis: dict):
           """验证分析是否充分"""
           
           # 检查是否至少覆盖 3 个维度
           covered = len(analysis.get("dimensions", {}))
           if covered < 3:
               raise ValueError("至少需要 3 个维度")
           
           # 允许自定义维度
           custom = [d for d in analysis["dimensions"] 
                    if d not in SUGGESTED_DIMENSIONS]
           # 自定义维度是允许的
   ```

3. **更新文档** (1 天)
   ```markdown
   # skills/runtime-protocol.md (更新)
   
   ## 分析维度
   
   **建议考虑的维度**（不是强制）：
   - vulnerability_family
   - parameter
   - encoding
   - ...
   
   **要求**：
   - 至少覆盖 3 个维度
   - 可以添加自定义维度
   - 例如："timing_differential"、"cache_poisoning"
   ```

**Expected Outcome:**
- ✅ AI 可以探索新的攻击角度
- ✅ 不被固定框架限制思维
- ✅ 保持最低质量要求（至少 3 个维度）

---

### Phase 5: 智能 Coverage Matrix，减轻心智负担
**Status:** not_started  
**Duration:** 1 周  
**Priority:** MEDIUM

**目标：** 预过滤 Coverage Matrix，只显示高价值组合

**问题分析：**
```text
当前：
  AI 看到 50 个 "untested" 单元格
  → 焦虑："我需要测试所有这些吗？"
  → 困惑："但这只是建议..."
  → 浪费 tokens 纠结

改进后：
  AI 看到 10 个 "高价值未测试" 组合
  → 清晰："这 10 个最值得测试"
  → 专注：立即开始测试
```

**智能过滤逻辑：**

```python
# tools/coverage_matrix.py (增强)

class IntelligentCoverageMatrix:
    """智能覆盖矩阵"""
    
    def get_high_value_gaps(self, target: str):
        """只返回高价值的未测试组合"""
        
        matrix = self._build_full_matrix(target)
        
        # 1. 根据技术栈排除不可能的组合
        tech_stack = get_tech_stack(target)
        if "node.js" in tech_stack:
            matrix = exclude(matrix, "java_deserialization")
        if is_static_site(target):
            matrix = exclude(matrix, ["sqli", "rce", "ssrf"])
        
        # 2. 根据已有证据提升优先级
        evidence = get_evidence(target)
        if "admin_endpoint" in evidence:
            boost_priority(matrix, "authz", +10)
        if "graphql" in evidence:
            boost_priority(matrix, "graphql_*", +10)
        
        # 3. 只返回 top 10
        gaps = sorted(matrix, key=lambda x: x["priority"], reverse=True)
        return gaps[:10]
```

**Tasks:**

1. **实现智能过滤** (3-4 天)
   - 技术栈过滤
   - 证据驱动优先级
   - Top K 限制

2. **添加优先级解释** (1 天)
   ```python
   {
       "endpoint": "/api/orders",
       "vuln_class": "idor",
       "priority": 85,
       "reason": "发现了 admin 端点 (+10) + numeric ID 参数 (+5)"
   }
   ```

3. **更新 CLAUDE.md** (1 天)
   ```markdown
   ## Coverage Matrix 使用
   
   Coverage Matrix 已预过滤，只显示最值得测试的组合：
   - 排除了不可能的组合（基于技术栈）
   - 基于已有证据排序
   - 只显示 top 10
   
   你可以：
   - 直接测试这些高价值组合
   - 或者基于你的判断选择其他方向
   ```

**Expected Outcome:**
- ✅ 减少 AI 的心智负担
- ✅ 聚焦高价值测试
- ✅ 保持 AI 的自主决策权

---

### Phase 6: 增强记忆系统，主动推荐
**Status:** not_started  
**Duration:** 1 周  
**Priority:** MEDIUM

**目标：** 记忆系统主动推荐，而非被动查询

**问题分析：**
```text
当前：被动查询
  AI: "让我查询一下历史模式..."
  AI: pattern_db.match(vuln_class="idor", tech_stack=["nextjs"])
  AI: "好的，看到了 3 个历史模式"

改进后：主动推荐
  System: "基于技术栈和历史成功率，推荐先测试 UUID v4 枚举"
  AI: "好的，我先测试这个"
```

**Tasks:**

1. **实现智能 Pattern Matching** (2-3 天)
   ```python
   # memory/pattern_db.py (增强)
   
   def match_smart(self, target_profile: dict, vuln_class: str = None):
       """智能匹配：相似度 + 准确率 + 时间衰减"""
       
       patterns = self.read_all()
       scored = []
       
       for p in patterns:
           score = 0
           
           # 技术栈相似度 (40%)
           tech_sim = jaccard_similarity(
               target_profile.get("tech_stack", []),
               p["tech_stack"]
           )
           score += tech_sim * 0.4
           
           # 校准准确率 (30%)
           calibration = get_calibration(p)
           precision = calibration.get("precision", 0.5)
           score += precision * 0.3
           
           # Payout 归一化 (20%)
           payout_norm = min(p.get("payout", 0) / 10000, 1.0)
           score += payout_norm * 0.2
           
           # 时间衰减 (10%)
           age_months = months_since(p["ts"])
           time_weight = max(0, 1.0 - age_months / 24)
           score += time_weight * 0.1
           
           scored.append((p, score))
       
       return sorted(scored, key=lambda x: x[1], reverse=True)
   ```

2. **创建主动推荐系统** (2 天)
   ```python
   # memory/recommender.py (NEW)
   
   class MemoryRecommender:
       """基于记忆的主动推荐"""
       
       def recommend_next_action(self, target: str):
           """推荐下一步行动"""
           
           profile = load_target_profile(target)
           patterns = PatternDB().match_smart(profile)
           
           if not patterns:
               return {"action": "explore", "reason": "无历史模式"}
           
           top = patterns[0]
           score = top[1]
           
           if score > 0.7:  # 高信心
               return {
                   "action": "focused_test",
                   "vuln_class": top[0]["vuln_class"],
                   "technique": top[0]["technique"],
                   "confidence": score,
                   "reason": f"在 {top[0]['target']} 成功过 (${top[0].get('payout', 0)})"
               }
           elif score > 0.4:  # 中等信心
               return {
                   "action": "quick_test",
                   "vuln_class": top[0]["vuln_class"],
                   "confidence": score
               }
           else:
               return {"action": "explore", "reason": "低置信度"}
   ```

3. **集成到启动流程** (1 天)
   - 每次 `/hunt` 开始时自动推荐
   - 推荐显示在 AI 上下文中
   - AI 可以采纳或忽略

4. **添加记忆维护** (1 天)
   ```python
   # memory/maintenance.py (NEW)
   
   def archive_low_value_patterns():
       """归档低价值模式"""
       
       patterns = PatternDB().read_all()
       
       for p in patterns:
           # 12 月未使用 → 归档
           if months_since_used(p) > 12:
               archive(p)
           
           # 准确率 <0.3 且样本 >=10 → 归档
           cal = get_calibration(p)
           if cal["precision"] < 0.3 and cal["samples"] >= 10:
               archive(p)
   ```

**Expected Outcome:**
- ✅ AI 自动获得历史经验推荐
- ✅ Pattern Matching 准确率提升 40-60%
- ✅ 跨目标学习效果显著提升

---

### Phase 7: 动态时间预算，支持深度探索
**Status:** not_started  
**Duration:** 3-5 天  
**Priority:** LOW

**目标：** 根据信号强度动态调整时间预算

**问题分析：**
```text
当前：固定时间限制
  Gate 0: 30s
  5-minute rule: 5min
  
问题：可能错过需要多步推理的深层漏洞

例子：
  1. 发现奇怪的 UUID 格式 (30s)
  2. 猜测是 base64 编码 (1min)
  3. 解码发现 JSON 结构 (2min)
  4. 发现可注入字段 (3min)
  5. 构造 payload (4min)
  6. 发现需要签名 (5min) ← 时间到！
  7. 分析签名算法... [被迫停止]
  
  实际上 8-10 步可能找到 Critical 漏洞
```

**Tasks:**

1. **实现信号强度评估** (2 天)
   ```python
   # tools/signal_strength.py (NEW)
   
   class SignalStrength(str, Enum):
       WEAK = "weak"      # 30s-1min
       MEDIUM = "medium"  # 5-10min
       STRONG = "strong"  # 15-30min
   
   def assess_signal(evidence: dict) -> SignalStrength:
       """评估信号强度"""
       
       # 强信号：部分证实的发现
       if evidence.get("partial_success"):
           return SignalStrength.STRONG
       
       # 中等信号：有依据的假设
       if evidence.get("based_on_pattern"):
           return SignalStrength.MEDIUM
       
       # 弱信号：低成功率
       return SignalStrength.WEAK
   ```

2. **更新时间预算规则** (1 天)
   ```markdown
   # rules/time-budget.md (NEW)
   
   ## 动态时间预算
   
   根据信号强度调整：
   
   - **弱信号**（低成功率）
     - 基础时间：30s-1min
     - 快速验证，快速放弃
   
   - **中等信号**（有依据的假设）
     - 基础时间：5-10min
     - 深入探索，但有上限
   
   - **强信号**（部分证实的发现）
     - 基础时间：15-30min
     - 完整证明，可以申请延长
   
   ## 时间延长申请
   
   当 AI 主动说"我看到了强烈的证据"时：
   - 允许申请延长时间预算
   - 需要说明理由和预期收益
   ```

3. **更新 CLAUDE.md** (1 天)

**Expected Outcome:**
- ✅ 支持深度探索复杂漏洞
- ✅ 不在弱信号上浪费时间
- ✅ 平衡效率和深度

---

### Phase 8: 集成测试与验证
**Status:** not_started  
**Duration:** 1 周  
**Priority:** HIGH

**目标：** 确保所有改进正常工作

**Tasks:**

1. **运行完整测试套件** (1 天)
   - 所有 3,474 个测试应通过
   - 修复任何回归

2. **端到端测试** (2 天)
   - `/recon` → `/hunt` → `/validate` → `/report`
   - 测试新的知识加载机制
   - 测试工具置信度
   - 测试智能推荐

3. **性能基准测试** (2 天)
   ```bash
   # 对比指标
   
   Before (当前):
   - AI 决策时间：平均 30s
   - 知识卡片加载：0-2 张（固定）
   - 重复验证率：60%
   
   After (改进后):
   - AI 决策时间：平均 10s (提升 3x)
   - 知识卡片加载：按需，平均 4-6 张
   - 重复验证率：20% (减少 67%)
   ```

4. **真实目标测试** (2 天)
   - 选择 2-3 个已知目标
   - 对比改进前后的表现

**Expected Outcome:**
- ✅ 所有测试通过
- ✅ 性能提升达标
- ✅ 真实场景验证

---

### Phase 9: 文档更新
**Status:** not_started  
**Duration:** 3 天  
**Priority:** MEDIUM

**Tasks:**

1. **更新 CLAUDE.md** (1 天)
   - 新的知识加载机制
   - 工具置信度说明
   - 动态时间预算

2. **创建迁移指南** (1 天)
   - `docs/ai-capability-liberation.md`
   - 说明 7 个改进点
   - 使用示例

3. **更新 README** (1 天)
   - 突出 AI 能力释放
   - 更新架构图

**Expected Outcome:**
- ✅ 完整的文档
- ✅ 清晰的使用指南

---

## Decisions Made

| Date | Decision | Rationale |
|------|----------|-----------|
| 2026-09-11 | 不重构架构，专注释放 AI 能力 | 架构已经很优秀 (9.1/10)，问题在于限制了 AI |
| 2026-09-11 | 保留所有核心机制 | Owner、Autopilot、记忆系统都很优秀 |
| 2026-09-11 | 移除中间层和人为限制 | Context Pack、固定卡片数、强制维度都限制 AI |
| 2026-09-11 | 工具三档信任模型 | 消除 "Advisory" 矛盾 |
| 2026-09-11 | Scanner 做穷举，AI 做推理 | 各自做擅长的事 |

---

## Errors Encountered

| Error | Phase | Resolution |
|-------|-------|------------|
| - | - | - |

---

## Risks & Mitigations

| Risk | Impact | Probability | Mitigation |
|------|--------|-------------|------------|
| 移除 Context Pack 破坏现有流程 | MEDIUM | LOW | 保留代码，逐步迁移 |
| 工具置信度判断不准 | MEDIUM | MEDIUM | 可以手动覆盖，逐步调优 |
| 智能推荐误导 AI | LOW | LOW | AI 可以忽略推荐 |
| 测试覆盖不足 | LOW | LOW | 保持所有 3,474 个测试 |

---

## Success Metrics

**核心指标：**

| 指标 | 当前 | 目标 | 测量方法 |
|------|------|------|----------|
| AI 决策速度 | 30s | 10s | 端到端测试计时 |
| 知识卡片加载 | 固定 0-2 张 | 按需 4-6 张 | 日志统计 |
| 重复验证率 | 60% | 20% | 分析 AI 行为日志 |
| 测试覆盖深度 | baseline | +40-60% | 发现的漏洞数量 |
| Pattern Matching 准确率 | baseline | +40-60% | 推荐成功率 |

**质量指标：**
- 测试通过率：100% (3,474/3,474)
- 核心功能保留：100%
- 文档完整性：100%

---

## Technical Debt Addressed

**移除的限制：**
1. ✅ Context Pack 中间层（3,552 行过滤逻辑）
2. ✅ 固定 0-2 张知识卡限制
3. ✅ 强制 7 维度要求
4. ✅ "Advisory" 工具输出矛盾
5. ✅ Scanner 能力刻意削弱
6. ✅ Coverage Matrix 心智负担
7. ✅ 固定时间预算

**保留的优秀设计：**
1. ✅ 五平面架构
2. ✅ 状态 Owner 机制 (8/8 完美)
3. ✅ Autopilot 引擎 (9.17/10)
4. ✅ 记忆系统 (JSONL, 跨目标学习)
5. ✅ 测试覆盖 (3,474 个测试)
6. ✅ MCP 集成

---

## Resources & Dependencies

**人力资源：**
- 主要开发者：1 人
- 预计工作量：4-6 周全职

**技术依赖：**
- Python 3.10+
- 现有工具链
- 测试框架 (pytest)

**时间线：**
- Phase 0: 3-5 天（修复当前问题）
- Phase 1-7: 4-5 周（能力释放）
- Phase 8-9: 1 周（测试和文档）

---

## Notes

**核心哲学：**
> "解放 AI 的思考能力，约束 AI 的行为边界"

**这次改进的本质：**
- ❌ 不是重构架构（架构已经很好）
- ✅ 是移除限制 AI 能力的障碍
- ✅ 让 AI 自由思考，自主决策
- ✅ 同时保持行为边界（红线规则、验证门）

**关键区别：**

| 维度 | 当前 | 改进后 |
|------|------|--------|
| 知识获取 | 系统推荐 0-2 张卡 | AI 自己搜索按需加载 |
| 工具结果 | "这只是建议" | "HIGH 置信度可采信" |
| 测试策略 | AI 构造 payload | Scanner 穷举 + AI 验证 |
| 思考框架 | 强制 7 维度 | 建议维度 + 自定义 |
| 测试覆盖 | 50 个 untested | 10 个高价值 |
| 历史学习 | AI 主动查询 | 系统主动推荐 |
| 时间预算 | 固定 30s/5min | 信号驱动动态调整 |

**预期效果：**
- AI 决策更快（3-5x）
- AI 覆盖更深（+40-60%）
- AI 学习更好（跨目标学习）
- 但仍受约束（红线、验证门）

---

## Appendix

**相关文档：**
- `findings.md` - 完整审核发现（2026-09-04）
- `progress.md` - 历史审核记录
- `CHANGELOG.md` - 版本历史

**关键文件：**
- `CLAUDE.md` - AI 工作指南
- `tools/vuln_scanner.sh` - Scanner
- `memory/pattern_db.py` - 记忆系统
- `tools/autopilot_state.py` - Autopilot

**实验分支：**
- `main` - 当前生产版本 (v4.4.1)
- `feature/ai-capability-liberation` - 改进分支（待创建）
