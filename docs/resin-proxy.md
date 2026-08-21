# Resin 出口代理池（ccst1）

VPS 命令行默认出口。非秘密连接信息在仓库根目录 `config.json` → `resin`，Token 在 `.env` → `RESIN_PROXY_TOKEN`；**mode 不要写进 config**。Resin 可用时默认 mode 是 **sticky**，同一目标/任务固定一个 Account。

不依赖 Burp。主工具：`curl` / `httpx` / `nuclei` / `ffuf` / `katana` / `python3 tools/hunt.py`。

`hunt.py` **不会**自动读 `resin` 段；需要走代理时在 shell 里 `export http(s)_proxy`，或给工具显式 `-proxy` / `-p` / `-x`。

---

## 1. config（只存非秘密连接事实）

```json
"resin": {
  "enabled": true,
  "host": "YOUR_RESIN_HOST",
  "port": 2260,
  "auth_version": "V1",
  "platform": "Default",
  "no_proxy": "localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
  "probe_url": "https://api.ipify.org"
}
```

```dotenv
# .env
RESIN_PROXY_TOKEN=YOUR_RESIN_PROXY_TOKEN
```

改实例只改这里。`enabled: false` 表示本仓库默认不走 Resin。

读配置：

```bash
cd /home/fsh1t/tool/ccst1
python3 - <<'PY'
import json
from pathlib import Path
r=json.loads(Path("config.json").read_text()).get("resin") or {}
print(r)
PY
```

---

## 2. Mode 自判

| 任务信号 | mode | 用户名 |
|---|---|---|
| 公网目标的 `/recon`、httpx/nuclei/ffuf、无会话宽扫、登录/session/多步写 | **sticky** | `{platform}.{account}` |
| 用户显式要求轮换出口 | **rotate** | `{platform}`（`Default`） |
| 只能改 BaseURL | **reverse** | 路径 + 可选 `X-Resin-Account` |
| 只认 SOCKS / proxychains | **socks** | 同上 rotate/sticky |
| localhost / 内网 / RFC1918 | **bypass** | 不走代理（`no_proxy`） |

优先级：

1. localhost / 内网 / RFC1918 始终 bypass
2. 用户显式指定 mode > 默认策略
3. 其余公网目标流量默认 sticky，同一目标/任务复用 Account
4. rotate 只在用户显式要求时使用
5. **禁止**每个请求随机 Account
6. 出口受阻时，根据当前证据和请求预算决定复用或切换可用 sticky env 及重试次数，不设固定上限

### sticky 的 Account

稳定即可，例如：

- 用户给的账号 / user id / email  
- `{targetHost}-{role}`（role 缺省 `sess`）  
- 同一 job 固定：`hunt-{target}-{date}`  

登录前后不要换字符串。

---

## 3. 拼串（V1）

```text
HOST/PORT/PLATFORM        ← config.resin
TOKEN                     ← CredentialStore(.env): RESIN_PROXY_TOKEN
HTTP_ROTATE = http://{PLATFORM}:{TOKEN}@{HOST}:{PORT}
HTTP_STICKY = http://{PLATFORM}.{ACCOUNT}:{TOKEN}@{HOST}:{PORT}
SOCKS       = socks5h://{user}:{TOKEN}@{HOST}:{PORT}
REVERSE     = http://{HOST}:{PORT}/{TOKEN}/{PLATFORM}/https/{target-host}/...
              粘性时加头: X-Resin-Account: {ACCOUNT}
```

当前默认可复制：

```text
http://Default:YOUR_RESIN_PROXY_TOKEN@YOUR_RESIN_HOST:2260
http://Default.<account>:YOUR_RESIN_PROXY_TOKEN@YOUR_RESIN_HOST:2260
socks5h://Default:YOUR_RESIN_PROXY_TOKEN@YOUR_RESIN_HOST:2260
http://YOUR_RESIN_HOST:2260/YOUR_RESIN_PROXY_TOKEN/Default/https/
```

TOKEN 为空时不要拼 `user:pass@`。

---

## 4. 接线示例

### sticky（默认：recon、scanner、登录态）

```bash
export http_proxy="http://Default.target-sess:YOUR_RESIN_PROXY_TOKEN@YOUR_RESIN_HOST:2260"
export https_proxy="$http_proxy" ALL_PROXY="$http_proxy"
export no_proxy="localhost,127.0.0.1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"

python3 tools/hunt.py --target target.com --recon-only
# 或
P="$http_proxy"
httpx -l hosts.txt -proxy "$P"
nuclei -l urls.txt -p "$P"
ffuf -u https://target/FUZZ -w wordlist.txt -x "$P"
```

### rotate（仅用户显式要求）

```bash
export http_proxy="http://Default:YOUR_RESIN_PROXY_TOKEN@YOUR_RESIN_HOST:2260"
export https_proxy="$http_proxy"
```

### reverse（只能改 BaseURL）

```bash
curl "http://YOUR_RESIN_HOST:2260/YOUR_RESIN_PROXY_TOKEN/Default/https/api.ipify.org" \
  -H "X-Resin-Account: user-42"
```

路径里协议字段只写 `http`/`https`。

### 从 config + CredentialStore 组装 export

```bash
cd /home/fsh1t/tool/ccst1
# 默认 sticky；同一目标/任务保持 ACCOUNT 不变
eval "$(MODE=sticky ACCOUNT=target-sess python3 - <<'PY'
import json, os
from pathlib import Path
from tools.credential_store import CredentialStore
r=json.loads(Path("config.json").read_text()).get("resin") or {}
if r.get("enabled") is False:
    raise SystemExit(0)
host=r.get("host","YOUR_RESIN_HOST"); port=int(r.get("port",2260))
token=CredentialStore(Path(".env")).get("RESIN_PROXY_TOKEN",""); plat=r.get("platform") or "Default"
mode=os.environ.get("MODE","sticky"); acc=os.environ.get("ACCOUNT","default").strip() or "default"
user=f"{plat}.{acc}" if mode=="sticky" else plat
auth=f"{user}:{token}@" if token else ""
proxy=f"http://{auth}{host}:{port}"
no=r.get("no_proxy","localhost,127.0.0.1")
print(f"export http_proxy={proxy!r}")
print(f"export https_proxy={proxy!r}")
print(f"export ALL_PROXY={proxy!r}")
print(f"export no_proxy={no!r}")
print(f"export RESIN_BASE=http://{host}:{port}")
PY
)"
```

---

## 5. 冒烟

```bash
curl -sS "http://YOUR_RESIN_HOST:2260/healthz"
curl -x "http://YOUR_RESIN_HOST:2260" -U "Default:YOUR_RESIN_PROXY_TOKEN" https://api.ipify.org
```

---

## 6. 与 slash 协作

| 流程 | mode |
|---|---|
| `/recon`、`hunt.py --recon-only` | sticky |
| `/hunt` 未认证宽扫、`/scan-cves` | sticky |
| 登录后继续测、角色差分 | sticky |
| `/autopilot` | sticky |
| 用户明确要求轮换 IP | rotate |
| 内网目标 | bypass |

给操作者/Agent 的最短输出：

```text
mode: rotate|sticky|...
why: <一句话>
proxy: <最终串>
verify: <一条 curl>
```

任务已能推断 mode 时，不要反问「要轮换还是粘性」。

---

## 7. 故障

| 现象 | 处理 |
|---|---|
| 407 | V1 用户名/密码是否与 config 一致 |
| 超时 | 节点；是否该 bypass 内网 |
| 粘性不粘 | Account 是否变化；是否误用 rotate 串 |
| 工具没走代理 | 是否 export 或显式 `-proxy` |
| lease 爆炸 | 批量是否每请求新 Account → 改回 rotate |

---

## 8. Burp（可选）

本 VPS 默认无 Burp。另有图形机时上游填 `host:port` + `Default` 或 `Default.<account>` + token。等价验证用 §5 curl。

---

## 9. inherit-lease（可选）

登录前临时身份 → 登录后稳定身份：

```bash
curl -sS -X POST \
  "http://YOUR_RESIN_HOST:2260/YOUR_RESIN_PROXY_TOKEN/api/v1/Default/actions/inherit-lease" \
  -H "Content-Type: application/json" \
  -d '{"parent_account":"temp-login-7","new_account":"user-alice"}'
```

`parent_account` 不要全局复用同一个串。
