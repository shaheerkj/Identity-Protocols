# OpenID Connect (OIDC): A Technical Deep Dive

> **Prerequisite:** This document assumes thorough knowledge of OAuth 2.0 — grant types, token mechanics, PKCE, and security considerations. Basic OAuth 2.0 concepts are not re-explained.  
> **Audience:** Security engineers, IAM practitioners, cloud security professionals (SC-200, AZ-500, cloud IAM roles).

---

## Table of Contents

1. [Context and Positioning](#1-context-and-positioning)
2. [OIDC Architecture and Components](#2-oidc-architecture-and-components)
3. [ID Token Deep Dive](#3-id-token-deep-dive)
4. [OIDC Flow Internals](#4-oidc-flow-internals)
5. [Protocol Endpoints and Discovery](#5-protocol-endpoints-and-discovery)
6. [Advanced Parameters and Behavior](#6-advanced-parameters-and-behavior)
7. [Token Validation and Trust Chain](#7-token-validation-and-trust-chain)
8. [End-to-End OIDC Exchange](#8-end-to-end-oidc-exchange)
9. [Security Deep Dive](#9-security-deep-dive)
10. [Best Practices and Modern Recommendations](#10-best-practices-and-modern-recommendations)

---

## 1. Context and Positioning

### 1.1 OIDC as a Layer, Not a Replacement

OpenID Connect ([specification](https://openid.net/specs/openid-connect-core-1_0.html)) is a thin **identity layer** built on top of OAuth 2.0. It does not replace OAuth 2.0 — it extends it by answering the question OAuth deliberately avoided:

> *"Who is the user that just authorized this request?"*

The extension is minimal by design:

- Adds a new token type: the **ID Token** (a signed JWT asserting user identity)
- Adds a new scope: `openid` (signals to the AS that OIDC is being used)
- Adds a new endpoint: **UserInfo** (for fetching additional identity claims)
- Adds new parameters: `nonce`, `prompt`, `max_age`, `acr_values`, `login_hint`
- Standardizes a **discovery document** and **JWKS endpoint**

Every other mechanism — flows, token endpoint, PKCE, redirect URIs, client registration — is inherited from OAuth 2.0 unchanged.

### 1.2 The Protocol Boundary

The separation is precise:

| Layer          | Protocol  | Token        | Question Answered               |
| -------------- | --------- | ------------ | ------------------------------- |
| Authorization  | OAuth 2.0 | Access Token | Is this client allowed to do X? |
| Authentication | OIDC      | ID Token     | Who is the authenticated user?  |

This boundary is not cosmetic. Confusing the two — using an access token as proof of identity, or sending an ID Token to an API — is a significant security mistake covered in Section 9.

### 1.3 Adoption and Ecosystem

OIDC is the dominant federated identity protocol for modern web, mobile, and cloud systems. It underpins:

- Google Identity Platform, Microsoft Entra ID (Azure AD), Apple Sign In
- Enterprise SSO (Okta, Auth0, Ping Identity, Keycloak)
- Kubernetes service account tokens (projected volumes)
- GitHub Actions OIDC tokens for cloud federation
- AWS IAM Identity Center, GCP Workload Identity Federation

---

## 2. OIDC Architecture and Components

### 2.1 Identity Provider (IdP) vs Authorization Server

In pure OAuth 2.0, the **Authorization Server (AS)** issues access tokens and manages consent. In OIDC, this same server takes on an additional role: **Identity Provider (IdP)**.

The conceptual difference:

| Role                     | Function                                       | Output                      |
| ------------------------ | ---------------------------------------------- | --------------------------- |
| **Authorization Server** | Authorizes client access to resources          | Access Token, Refresh Token |
| **Identity Provider**    | Asserts the identity of the authenticated user | ID Token, UserInfo claims   |

In most deployments, a single server plays both roles simultaneously. The distinction matters architecturally because:

- An AS can exist without being an IdP (pure OAuth 2.0 deployment)
- An IdP *must* implement OAuth 2.0 as its transport layer (per OIDC spec)
- Some enterprise architectures federate a separate IdP (e.g., an on-premises Active Directory Federation Services) into a cloud AS (e.g., Azure AD), creating a chain

### 2.2 Relying Party (RP) vs OAuth Client

In OIDC, the OAuth **Client** is referred to as the **Relying Party (RP)**. The terminological shift is intentional: the RP *relies* on the IdP's assertion of identity.

Behavioral differences from a pure OAuth client:

- The RP **must** validate the ID Token — this is non-optional and precisely specified in the spec
- The RP tracks session state and may initiate **logout** via the RP-initiated logout protocol
- The RP must handle the `nonce` parameter: generate it, bind it to the session, and verify it in the ID Token
- The RP is registered with the IdP with additional metadata beyond standard OAuth client registration (e.g., `id_token_signed_response_alg`, `userinfo_encrypted_response_alg`)

### 2.3 UserInfo Endpoint vs ID Token

OIDC provides two ways to receive identity claims about the user. They serve different purposes:

|               | ID Token                   | UserInfo Endpoint                  |
| ------------- | -------------------------- | ---------------------------------- |
| **Format**    | Signed JWT                 | JSON (optionally signed/encrypted) |
| **Delivery**  | In the token response      | Via separate HTTP GET request      |
| **Bound to**  | Authentication event       | Current user (uses access token)   |
| **Purpose**   | Prove who authenticated    | Fetch additional profile data      |
| **Freshness** | Snapshot at auth time      | May reflect current profile state  |
| **Latency**   | Zero (already in response) | Requires extra network round-trip  |

**When to use which:**

- Use the **ID Token** for authentication decisions (who logged in, when, how)
- Use the **UserInfo endpoint** for profile data you need but that doesn't need to be embedded in every token (avoids bloating tokens)
- Never use UserInfo data for making authentication decisions — it's not cryptographically bound to the authentication event the same way the ID Token is

### 2.4 Trust Model and Metadata Discovery

The trust relationship in OIDC flows through:

1. **Client Registration** — The RP registers with the IdP (statically or dynamically via RFC 7591). The IdP issues `client_id` and optionally `client_secret`. Redirect URIs, allowed scopes, and token signing algorithms are registered here.

2. **Discovery** — The RP retrieves the IdP's metadata from `/.well-known/openid-configuration` (covered in Section 5). This document anchors all subsequent trust decisions.

3. **JWKS** — The RP fetches the IdP's public signing keys from the `jwks_uri` in the discovery document. All ID Token signatures are verified against these keys.

4. **Issuer Binding** — The `iss` claim in the ID Token must match the issuer in the discovery document. This is the root of the trust chain.

```
RP trusts IdP's discovery document
  → retrieves signing keys from jwks_uri
  → verifies ID Token signature with those keys
  → validates iss matches the trusted issuer
  → trusts the identity claims in the token
```

---

## 3. ID Token Deep Dive

The ID Token is the defining artifact of OIDC. It is a **JWS (JSON Web Signature)** — a signed JWT — that asserts the identity of the authenticated user.

### 3.1 JWT Structure

A JWT has three components, each Base64URL-encoded and concatenated with `.`:

```
BASE64URL(header) . BASE64URL(payload) . BASE64URL(signature)
```

#### Header

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "signing-key-2024-01"
}
```

| Field | Meaning                                                                                |
| ----- | -------------------------------------------------------------------------------------- |
| `alg` | Signing algorithm. Must be `RS256` or `ES256` in production. **Never `none`.**         |
| `typ` | Token type. `JWT` for standard tokens.                                                 |
| `kid` | Key ID. Used to look up the specific key in the JWKS endpoint to verify the signature. |

#### Payload (Claims)

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-a1b2c3d4",
  "aud": "myapp-client-id",
  "exp": 1700003600,
  "iat": 1700000000,
  "auth_time": 1699999800,
  "nonce": "n-0S6_WzA2Mj",
  "azp": "myapp-client-id",
  "at_hash": "MTIzNDU2Nzg5MDEyMzQ",
  "c_hash": "LDktKdoQak3Pk0cnXxCltA",
  "acr": "urn:mace:incommon:iap:silver",
  "amr": ["pwd", "mfa"],
  "name": "Shaheryar Ahmed",
  "email": "shaheryar@example.com",
  "email_verified": true
}
```

#### Signature

```
RSA_SHA256(
  base64url(header) + "." + base64url(payload),
  IdP_private_key
)
```

The signature is verified by the RP using the IdP's **public key** retrieved from the JWKS endpoint.

---

### 3.2 Required and Optional Claims

#### Required Claims (MUST be present in every ID Token)

| Claim | Type            | Description                                                                                                                                                                                   |
| ----- | --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `iss` | String (URL)    | Issuer identifier. Exact URL of the IdP. Must be HTTPS. Must match `issuer` in discovery document.                                                                                            |
| `sub` | String          | Subject identifier. A stable, unique, opaque identifier for the user **within this issuer**. Not an email — never changes even if the user changes their email. Maximum 255 ASCII characters. |
| `aud` | String or Array | Audience. Must include the `client_id` of the RP. If an array, all entries must be trusted.                                                                                                   |
| `exp` | NumericDate     | Expiry. Unix timestamp. The RP must reject the token if current time ≥ `exp`.                                                                                                                 |
| `iat` | NumericDate     | Issued At. Unix timestamp of when the token was issued.                                                                                                                                       |

#### Conditionally Required Claims

| Claim       | Required When                               | Description                                                                                                           |
| ----------- | ------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| `auth_time` | `max_age` was requested, or IdP includes it | Unix timestamp of when the user actually authenticated. Different from `iat` — token issuance can lag authentication. |
| `nonce`     | `nonce` was sent in the auth request        | Echo of the `nonce` value. Used to bind the ID Token to a specific authentication request.                            |
| `acr`       | `acr_values` was requested                  | Authentication Context Class Reference. Indicates the strength of authentication (e.g., MFA level).                   |

#### Optional but Commonly Used Claims

| Claim     | Description                                                                                                                                         |
| --------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `azp`     | Authorized Party. The `client_id` of the party the token was issued *for* — relevant when `aud` contains multiple values.                           |
| `at_hash` | Access Token Hash. Left half of SHA-256 of the access token, Base64URL-encoded. Cryptographically binds the ID Token to the access token.           |
| `c_hash`  | Code Hash. Left half of SHA-256 of the authorization code. Cryptographically binds the ID Token to the authorization code. Required in Hybrid Flow. |
| `amr`     | Authentication Methods References. Array of strings indicating how authentication was performed (e.g., `["pwd", "otp"]`).                           |
| `sid`     | Session ID. Identifier for the authentication session. Used in logout flows.                                                                        |

#### Standard Profile Claims (from `profile` scope)

`name`, `given_name`, `family_name`, `middle_name`, `nickname`, `preferred_username`, `profile`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at`

#### Standard Email Claims (from `email` scope)

`email`, `email_verified`

#### Standard Phone Claims (from `phone` scope)

`phone_number`, `phone_number_verified`

---

### 3.3 Token Signing (JWS) and Optional Encryption (JWE)

#### JWS (JSON Web Signature) — The Default

All ID Tokens MUST be signed. Supported algorithms:

| Algorithm | Type            | Notes                                                                                                                                  |
| --------- | --------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `RS256`   | RSA + SHA-256   | Most common. Asymmetric — IdP signs with private key, RP verifies with public key.                                                     |
| `ES256`   | ECDSA + SHA-256 | More efficient than RSA. Increasingly preferred.                                                                                       |
| `HS256`   | HMAC + SHA-256  | Symmetric — requires the RP and IdP to share a secret. **Avoid in most deployments.** Vulnerable to key confusion attacks (Section 9). |
| `none`    | None            | No signature. **MUST NEVER be accepted in production.**                                                                                |

The RP must be configured to accept only specific `alg` values. Accepting `alg` from the token header without validation is a critical vulnerability.

#### JWE (JSON Web Encryption) — Optional

For sensitive deployments, the ID Token can additionally be **encrypted** (producing a JWE). The encryption wraps the entire JWS:

```
JWE(JWS(payload)) → encrypted ID Token
```

The RP registers its public encryption key with the IdP. The IdP encrypts the JWS using the RP's public key. Only the RP can decrypt it with its private key.

Relevant fields when encryption is used:

- `id_token_encrypted_response_alg` — key agreement algorithm (e.g., `RSA-OAEP`)
- `id_token_encrypted_response_enc` — content encryption algorithm (e.g., `A256GCM`)

JWE is rare in practice but important for high-assurance or regulated environments where token contents must not be visible to intermediaries.

---

### 3.4 Key Rotation and JWKS Endpoint

The IdP regularly rotates its signing keys. The JWKS (JSON Web Key Set) endpoint exposes all current public keys:

```http
GET /jwks HTTP/1.1
Host: auth.example.com
```

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "signing-key-2024-01",
      "alg": "RS256",
      "n": "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGyw...",
      "e": "AQAB"
    },
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "signing-key-2024-02",
      "alg": "RS256",
      "n": "new-key-modulus...",
      "e": "AQAB"
    }
  ]
}
```

**Key rotation process:**

1. IdP generates a new key pair, publishes new public key in JWKS (alongside old key)
2. IdP begins signing new tokens with the new private key
3. Old tokens (signed with old key) remain verifiable using the old public key still in JWKS
4. After old tokens expire, IdP removes old public key from JWKS

**RP caching strategy:**

- Cache JWKS with a reasonable TTL (e.g., 1 hour)
- If signature verification fails with cached keys, **re-fetch JWKS once** and retry
- Do not re-fetch on every token validation (DDoS risk to IdP)
- Use `kid` from the token header to select the correct key — avoid trying all keys

---

### 3.5 Sample ID Token — Full Annotated Example

**Encoded:**

```
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNpZ25pbmcta2V5LTIwMjQtMDEifQ
.
eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWExYjJjM2Q0IiwiYXVkIjoibXlhcHAtY2xpZW50LWlkIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsImF1dGhfdGltZSI6MTY5OTk5OTgwMCwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJhenAiOiJteWFwcC1jbGllbnQtaWQiLCJhdF9oYXNoIjoiTVRJek5EVTJOemM0T1RBeE1qTTAiLCJhY3IiOiJ1cm46bWFjZTppbmNvbW1vbjppYXA6c2lsdmVyIiwiYW1yIjpbInB3ZCIsIm1mYSJdLCJuYW1lIjoiU2hhaGVyeWFyIEFobWVkIiwiZW1haWwiOiJzaGFoZXJ5YXJAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0
.
SIGNATURE
```

**Decoded Payload:**

```json
{
  "iss": "https://auth.example.com",      // Issuer — must match discovery doc
  "sub": "user-a1b2c3d4",                 // Stable, opaque user ID — use this, not email
  "aud": "myapp-client-id",               // Audience — must match this RP's client_id
  "exp": 1700003600,                      // Expires: 2023-11-14T22:13:20Z
  "iat": 1700000000,                      // Issued: 2023-11-14T21:13:20Z (1 hour token)
  "auth_time": 1699999800,                // User actually authenticated 200s before issuance
  "nonce": "n-0S6_WzA2Mj",               // Must match nonce sent in auth request
  "azp": "myapp-client-id",              // Authorized party (same as aud here)
  "at_hash": "MTIzNDU2Nzg5MDEyMzQ",     // Binds this ID Token to the access token
  "acr": "urn:mace:incommon:iap:silver", // Authentication assurance level
  "amr": ["pwd", "mfa"],                  // Authenticated via password + MFA
  "name": "Shaheryar Ahmed",              // From profile scope
  "email": "shaheryar@example.com",       // From email scope
  "email_verified": true                  // IdP has confirmed this email
}
```

---

## 4. OIDC Flow Internals

OIDC uses the same underlying flows as OAuth 2.0 but modifies their behavior. The `openid` scope is what triggers OIDC behavior at the Authorization Server.

---

### 4.1 Authorization Code Flow (OIDC Context)

This is the standard OIDC flow. Identical to OAuth 2.0 Authorization Code Flow with OIDC-specific additions.

**What changes compared to pure OAuth 2.0:**

- `openid` is required in `scope`
- `nonce` should be sent (required if `response_type` includes `id_token`)
- Token endpoint returns an `id_token` in addition to `access_token`
- The RP must validate the ID Token before trusting any identity claims

#### Step 1: Authorization Request

```http
GET /authorize?
  response_type=code
  &client_id=myapp-client-id
  &redirect_uri=https://myapp.com/callback
  &scope=openid%20profile%20email
  &state=xK9mP2qR7vL4nJ1w
  &nonce=n-0S6_WzA2Mj
  &prompt=login
  &max_age=3600
HTTP/1.1
Host: auth.example.com
```

The `nonce` value must be:

- Cryptographically random (≥128 bits of entropy)
- Stored server-side or in a secure, HttpOnly session cookie
- Verified against the `nonce` claim in the returned ID Token

#### Step 2: Token Exchange

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(myapp-client-id:client_secret)

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://myapp.com/callback
```

#### Step 3: Token Response (OIDC)

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9.ACCESS...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "id_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InNpZ25pbmcta2V5LTIwMjQtMDEifQ.eyJpc3MiOi...",
  "scope": "openid profile email"
}
```

The `id_token` is exclusively in the token endpoint response. It is **never** sent to the Resource Server.

#### ID Token Validation (Step 4 — Critical)

Full validation process covered in Section 7. At minimum:

1. Verify the signature
2. Verify `iss`, `aud`, `exp`, `iat`
3. Verify `nonce` matches what was sent
4. If `at_hash` is present, verify it against the access token

---

### 4.2 Authorization Code + PKCE (Recommended Modern Flow)

PKCE and OIDC are independent extensions to OAuth 2.0. They compose seamlessly and should always be used together for public clients.

#### How They Interact

PKCE protects the **authorization code** from being stolen and exchanged by an attacker. OIDC adds the **ID Token** to the token response. Together:

- PKCE prevents code interception → attacker can't get tokens at all
- OIDC `nonce` prevents replay → even if an old ID Token is captured, it can't be replayed into a new session
- `at_hash` in the ID Token cryptographically binds the ID Token to the specific access token issued — prevents token substitution

#### Request (Combined PKCE + OIDC)

```http
GET /authorize?
  response_type=code
  &client_id=myapp-spa
  &redirect_uri=https://myapp.com/callback
  &scope=openid%20profile%20email
  &state=xK9mP2qR7vL4nJ1w
  &nonce=n-0S6_WzA2Mj
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
HTTP/1.1
Host: auth.example.com
```

The `nonce` serves a different purpose than `state`:

- `state` → CSRF protection for the OAuth redirect
- `nonce` → replay protection for the ID Token itself

Both must be present and validated.

---

### 4.3 Hybrid Flow

The Hybrid Flow allows the RP to receive some tokens **from the authorization endpoint** (via redirect) and other tokens **from the token endpoint** (via back-channel). It is defined by using specific `response_type` combinations.

#### `response_type` Values

| `response_type`       | From Auth Endpoint             | From Token Endpoint                   |
| --------------------- | ------------------------------ | ------------------------------------- |
| `code`                | code                           | access_token, id_token, refresh_token |
| `id_token`            | id_token                       | —                                     |
| `code id_token`       | code + id_token                | access_token, id_token, refresh_token |
| `code token`          | code + access_token            | id_token, refresh_token               |
| `code id_token token` | code + id_token + access_token | id_token, refresh_token               |

The most common Hybrid Flow uses `code id_token`:

```http
GET /authorize?
  response_type=code%20id_token
  &client_id=myapp-client-id
  &redirect_uri=https://myapp.com/callback
  &scope=openid%20profile
  &state=xK9mP2qR7vL4nJ1w
  &nonce=n-0S6_WzA2Mj
HTTP/1.1
Host: auth.example.com
```

**Response (via fragment):**

```
https://myapp.com/callback#
  code=SplxlOBeZQQYbYS6WxSbIA
  &id_token=eyJhbGciOiJSUzI1NiJ9...
  &state=xK9mP2qR7vL4nJ1w
```

The `id_token` returned from the authorization endpoint contains a `c_hash` claim:

```json
{
  "c_hash": "LDktKdoQak3Pk0cnXxCltA"
}
```

`c_hash` = Base64URL(left_half(SHA256(authorization_code)))

The RP verifies `c_hash` against the received `code` before using either. This binds the ID Token to the code, preventing substitution attacks.

#### Security Implications of Hybrid Flow

- Tokens returned in the authorization endpoint response travel via browser redirect (URL fragment or query string) — higher exposure risk
- The ID Token from the auth endpoint typically has fewer claims (it's a "hint") — the full ID Token with all claims comes from the token endpoint
- `c_hash` and `at_hash` are the critical security bindings — if validation is skipped, token substitution becomes possible
- **Modern recommendation:** Avoid Hybrid Flow unless there is a specific architectural reason. Authorization Code + PKCE achieves the same security goals with less complexity.

---

### 4.4 Implicit Flow (Historical)

In OIDC Implicit Flow, the ID Token (and optionally access token) were returned directly from the authorization endpoint via URL fragment:

```
https://myapp.com/callback#
  id_token=eyJhbGciOiJSUzI1NiJ9...
  &access_token=SlAV32hkKG
  &token_type=Bearer
  &expires_in=3600
  &state=xK9mP2qR7vL4nJ1w
```

**Why it existed:** Before PKCE, public clients had no secure way to use the Authorization Code Flow (no secret to authenticate the token exchange). The Implicit Flow removed the token exchange step entirely.

**Why it is deprecated:**

- ID Token in URL fragment → appears in browser history, server logs, proxy logs, `Referer` headers
- No refresh token support
- No `c_hash` or `at_hash` validation possible in the auth endpoint response for `response_type=id_token`
- PKCE makes it entirely unnecessary

**What replaced it:** Authorization Code + PKCE for all public clients.

---

## 5. Protocol Endpoints and Discovery

### 5.1 `/.well-known/openid-configuration`

The OIDC discovery document is a JSON document served at a well-known URL. It is the foundation of the trust model — the RP fetches this document to configure itself.

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: auth.example.com
```

#### Sample Discovery Document

```json
{
  "issuer": "https://auth.example.com",
  "authorization_endpoint": "https://auth.example.com/authorize",
  "token_endpoint": "https://auth.example.com/token",
  "userinfo_endpoint": "https://auth.example.com/userinfo",
  "jwks_uri": "https://auth.example.com/jwks",
  "registration_endpoint": "https://auth.example.com/register",
  "end_session_endpoint": "https://auth.example.com/logout",
  "revocation_endpoint": "https://auth.example.com/revoke",
  "introspection_endpoint": "https://auth.example.com/introspect",
  "device_authorization_endpoint": "https://auth.example.com/device_authorization",

  "scopes_supported": ["openid", "profile", "email", "phone", "offline_access"],
  "response_types_supported": ["code", "id_token", "code id_token", "code token"],
  "response_modes_supported": ["query", "fragment", "form_post"],
  "grant_types_supported": ["authorization_code", "refresh_token", "client_credentials"],

  "id_token_signing_alg_values_supported": ["RS256", "ES256"],
  "id_token_encryption_alg_values_supported": ["RSA-OAEP"],
  "id_token_encryption_enc_values_supported": ["A256GCM"],

  "userinfo_signing_alg_values_supported": ["RS256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt"
  ],

  "subject_types_supported": ["public", "pairwise"],
  "claim_types_supported": ["normal", "aggregated", "distributed"],
  "claims_supported": [
    "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
    "name", "email", "email_verified", "phone_number"
  ],

  "code_challenge_methods_supported": ["S256"],
  "request_parameter_supported": true,
  "request_uri_parameter_supported": true,
  "require_request_uri_registration": true,

  "frontchannel_logout_supported": true,
  "backchannel_logout_supported": true,
  "backchannel_logout_session_supported": true
}
```

#### Key Fields Explained

| Field                                   | Significance                                                                                     |
| --------------------------------------- | ------------------------------------------------------------------------------------------------ |
| `issuer`                                | The canonical IdP URL. **Must be HTTPS. Must match `iss` in all ID Tokens.**                     |
| `jwks_uri`                              | Where the RP fetches public signing keys.                                                        |
| `subject_types_supported`               | `public` = same `sub` for all RPs. `pairwise` = different `sub` per RP (privacy-preserving).     |
| `code_challenge_methods_supported`      | If `S256` is listed, PKCE is supported. If this field is absent, assume no PKCE support.         |
| `token_endpoint_auth_methods_supported` | How the client authenticates to the token endpoint. `private_key_jwt` is the most secure option. |
| `backchannel_logout_supported`          | Whether the IdP supports OIDC Back-Channel Logout (server-to-server session termination).        |

### 5.2 Dynamic Discovery Process

1. RP is configured with the IdP's **issuer URL** (e.g., `https://auth.example.com`)
2. RP constructs the discovery URL: `{issuer}/.well-known/openid-configuration`
3. RP fetches and caches the document
4. RP extracts endpoint URLs and supported capabilities
5. RP configures itself (sets `authorization_endpoint`, `token_endpoint`, `jwks_uri`, etc.)

This makes OIDC self-configuring — changing an IdP's endpoint URLs only requires updating the discovery document, not reconfiguring every RP.

### 5.3 JWKS Endpoint

Covered in Section 3.4. Key operational notes:

- The JWKS response may contain multiple keys (different `kid` values, key rotation overlap)
- The RP selects the key matching the `kid` in the token header
- If no matching `kid` is found, refresh the JWKS and retry **once**
- JWKS responses should be cached (respect `Cache-Control` headers, or default to ~1 hour TTL)

### 5.4 UserInfo Endpoint

```http
GET /userinfo HTTP/1.1
Host: auth.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN...
```

```json
{
  "sub": "user-a1b2c3d4",
  "name": "Shaheryar Ahmed",
  "given_name": "Shaheryar",
  "family_name": "Ahmed",
  "email": "shaheryar@example.com",
  "email_verified": true,
  "phone_number": "+92-300-1234567",
  "picture": "https://example.com/users/shaheryar/photo.jpg"
}
```

**Critical:** The `sub` in the UserInfo response MUST match the `sub` in the ID Token. If they don't match, the RP must reject the response — this would indicate a response substitution attack.

The UserInfo response can also be returned as a **signed JWT** (if the IdP supports `userinfo_signed_response_alg`), providing authenticity guarantees beyond the TLS transport.

### 5.5 Token Endpoint Differences in OIDC

The token endpoint behaves identically to OAuth 2.0 with one addition: when `openid` is in scope, the response includes `id_token`.

**Client authentication methods at the token endpoint:**

| Method                | How It Works                             | Security Level                             |
| --------------------- | ---------------------------------------- | ------------------------------------------ |
| `client_secret_basic` | `Authorization: Basic base64(id:secret)` | Standard                                   |
| `client_secret_post`  | `client_secret` in POST body             | Weaker (body logging risk)                 |
| `client_secret_jwt`   | JWT signed with the shared secret        | Stronger                                   |
| `private_key_jwt`     | JWT signed with client's private key     | Strongest — recommended for high-assurance |
| `none`                | No authentication (public clients)       | Must use PKCE                              |

`private_key_jwt` is the recommended method for confidential clients in high-security deployments. The client signs a JWT assertion with its private key; the IdP verifies with the registered public key. This eliminates the need to share any secret.

---

## 6. Advanced Parameters and Behavior

### 6.1 `nonce`

The `nonce` is a string value sent by the RP in the authorization request. The IdP embeds it verbatim in the ID Token as the `nonce` claim.

**Purpose:** Binds the ID Token to a specific authentication request, preventing ID Token replay attacks.

**Lifecycle:**

```
1. RP generates: nonce = cryptographically_random_string()
2. RP stores: session["nonce"] = nonce  (server-side, never in URL)
3. RP includes in auth request: &nonce=<value>
4. IdP embeds in ID Token: { "nonce": "<value>" }
5. RP validates: assert id_token_claims["nonce"] == session["nonce"]
6. RP invalidates: delete session["nonce"]  (single-use)
```

A `nonce` that is reused, predictable, or not validated defeats replay protection. The nonce must be:

- Cryptographically random (min 128 bits)
- Single-use (invalidated after one verification)
- Stored in a server-side session or HttpOnly cookie (not in localStorage)

### 6.2 `state`

Inherited from OAuth 2.0. In OIDC context: still for CSRF protection of the authorization redirect. Distinct from `nonce` — they protect different things at different layers.

`state` → protects the **OAuth redirect** (is this callback expected?)  
`nonce` → protects the **ID Token** (is this token for this session?)

Both must be present. Both must be validated.

### 6.3 `prompt`

Controls whether the IdP forces the user to interact, regardless of existing session state.

| Value            | Behavior                                                                                                                                                        |
| ---------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `none`           | No UI interaction. If authentication or consent is required, return an error (`login_required`, `interaction_required`). Used for silent authentication checks. |
| `login`          | Force re-authentication even if the user has an existing session. Useful for sensitive operations.                                                              |
| `consent`        | Force re-display of the consent screen even if the user has previously consented.                                                                               |
| `select_account` | Show an account selector even if only one session exists.                                                                                                       |

**`prompt=none` use case — silent token refresh in SPAs:**

```http
GET /authorize?
  response_type=code
  &client_id=myapp-spa
  &redirect_uri=https://myapp.com/silent-callback
  &scope=openid
  &prompt=none
  &nonce=new-nonce
  &code_challenge=...
```

This is done in a hidden iframe. If the user has an active session at the IdP, a new ID Token is issued silently. If not, the error is caught and the user is redirected to login.

### 6.4 `max_age`

Specifies the maximum elapsed time (in seconds) since the user's last active authentication. If `auth_time` in the ID Token indicates the user authenticated longer ago than `max_age`, the IdP must re-authenticate the user.

```http
GET /authorize?...&max_age=900
```

If `max_age=900`, the IdP must ensure the user authenticated within the last 15 minutes. If not, it forces re-login before issuing the token.

The RP must also validate: `current_time - auth_time ≤ max_age` on the received ID Token.

### 6.5 `acr_values`

Authentication Context Class Reference. The RP requests a specific assurance level for authentication:

```http
GET /authorize?...&acr_values=urn:mace:incommon:iap:silver%20urn:mace:incommon:iap:bronze
```

(Space-separated list, ordered by preference.)

The IdP includes the actual `acr` achieved in the ID Token:

```json
{ "acr": "urn:mace:incommon:iap:silver" }
```

Common ACR values:

- `urn:mace:incommon:iap:bronze` — password only
- `urn:mace:incommon:iap:silver` — password + second factor
- `urn:mace:incommon:iap:gold` — hardware token or biometric

The RP should verify the `acr` in the ID Token meets its minimum requirement for the requested operation.

### 6.6 `login_hint`

A hint to the IdP about which user is attempting to authenticate. Typically an email address or username. Allows the IdP to pre-populate the login form.

```http
GET /authorize?...&login_hint=user%40example.com
```

This is only a hint — the IdP may ignore it. The authenticated user's identity is always taken from the `sub` in the ID Token, not from `login_hint`.

### 6.7 `response_type` and `response_mode`

`response_type` defines which tokens are returned and from which endpoint (authorization or token). See Section 4.3 for the full table.

`response_mode` defines **how** the authorization endpoint delivers its response to the RP:

| Value        | Delivery Method                      | Notes                                                          |
| ------------ | ------------------------------------ | -------------------------------------------------------------- |
| `query`      | URL query string (`?code=...`)       | Default for `response_type=code`. Tokens visible in logs.      |
| `fragment`   | URL fragment (`#code=...`)           | Default for implicit flow. Not sent to server.                 |
| `form_post`  | HTTP POST with form data             | Most secure for front-channel. Response not in URL or logs.    |
| `jwt` (JARM) | Signed JWT containing all parameters | JWT Authorization Response Mode — advanced, provides integrity |

For `response_type=code`, prefer `response_mode=form_post` in high-security deployments to prevent authorization codes from appearing in server logs.

### 6.8 Scope Semantics in OIDC

| Scope            | Claims Returned                                                                                                                  |
| ---------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `openid`         | **Required.** Triggers OIDC. Returns `sub` at minimum. Without this, it's plain OAuth 2.0.                                       |
| `profile`        | `name`, `given_name`, `family_name`, `nickname`, `picture`, `website`, `gender`, `birthdate`, `zoneinfo`, `locale`, `updated_at` |
| `email`          | `email`, `email_verified`                                                                                                        |
| `phone`          | `phone_number`, `phone_number_verified`                                                                                          |
| `address`        | `address` (structured JSON object)                                                                                               |
| `offline_access` | Issues a `refresh_token`. Without this, no refresh token is issued in OIDC flows.                                                |

Claims may be delivered in the ID Token directly, from the UserInfo endpoint, or both — depending on IdP configuration. RPs should request claims from UserInfo for large payloads (avoids bloating tokens stored in session state).

---

## 7. Token Validation and Trust Chain

### 7.1 Full ID Token Validation Process

The RP MUST perform all of these checks. Skipping any is a security vulnerability.

```
Step 1: Decrypt (if encrypted)
  - If id_token is a JWE, decrypt using the RP's private key
  - The result is the underlying JWS

Step 2: Parse the JWT
  - Split by "."
  - Base64URL-decode header and payload (no key needed)
  - Do NOT trust claims until signature is verified

Step 3: Algorithm check
  - header["alg"] must be an algorithm the RP is configured to accept
  - REJECT if alg == "none"
  - REJECT if alg is not in the RP's allowlist

Step 4: Key selection
  - Use header["kid"] to select the key from the cached JWKS
  - If kid is not found, re-fetch JWKS once and retry
  - If still not found, REJECT

Step 5: Signature verification
  - Verify the JWT signature using the selected public key
  - REJECT if verification fails

Step 6: Issuer validation
  - payload["iss"] must exactly match the expected issuer
  - The expected issuer comes from the discovery document, not from the token itself
  - REJECT if mismatch

Step 7: Audience validation
  - payload["aud"] must contain the RP's client_id
  - If payload["aud"] is an array with multiple entries, verify payload["azp"] == client_id
  - REJECT if client_id is not in aud

Step 8: Expiry validation
  - current_time < payload["exp"]  (allow a small clock skew: ≤ 60 seconds)
  - REJECT if token is expired

Step 9: Issued-at validation
  - payload["iat"] should not be too far in the past (IdP-dependent, but flag if > 5 minutes old at receipt)
  - This is advisory, not strictly required, but helps detect old tokens

Step 10: Nonce validation (REQUIRED if nonce was sent)
  - payload["nonce"] must exactly match the nonce stored in the RP's session
  - REJECT if mismatch or if nonce is absent when it was sent in the request
  - Invalidate the stored nonce (single-use)

Step 11: auth_time validation (if max_age was sent)
  - current_time - payload["auth_time"] ≤ max_age (+ clock skew tolerance)
  - REJECT if the user authenticated too long ago

Step 12: acr validation (if acr_values was sent)
  - payload["acr"] must meet the minimum assurance level required
  - REJECT if the achieved acr is insufficient

Step 13: at_hash validation (if access_token was also received)
  - Compute: expected_at_hash = base64url(left_half(sha256(access_token)))
  - payload["at_hash"] must match expected_at_hash
  - REJECT if mismatch

Step 14: c_hash validation (Hybrid Flow, if code was also received)
  - Compute: expected_c_hash = base64url(left_half(sha256(code)))
  - payload["c_hash"] must match expected_c_hash
  - REJECT if mismatch
```

Only after all steps pass should the RP consider the authentication successful and trust the `sub` and other identity claims.

### 7.2 ID Token vs Access Token Validation

|                     | ID Token                   | Access Token (JWT)                      |
| ------------------- | -------------------------- | --------------------------------------- |
| **Who validates**   | Relying Party (client app) | Resource Server (API)                   |
| **Purpose**         | Prove who authenticated    | Prove permission to access resource     |
| **`aud` check**     | Must contain `client_id`   | Must contain Resource Server identifier |
| **`nonce` check**   | Required (if sent)         | Not applicable                          |
| **`at_hash` check** | RP validates               | Not applicable                          |
| **Scope check**     | Not applicable             | RS checks required scope                |
| **Send to API**     | NEVER                      | Always (in Bearer header)               |

A common misconfiguration: sending the ID Token to an API as a Bearer token. This is wrong because:

- The `aud` of the ID Token is the client, not the API
- The API would need to accept tokens with a different audience claim
- It blurs the authentication/authorization boundary

### 7.3 Local vs Remote Validation

| Method                     | Mechanism                                           | Pros                               | Cons                                               |
| -------------------------- | --------------------------------------------------- | ---------------------------------- | -------------------------------------------------- |
| **Local (JWT)**            | Verify signature, check claims locally              | Fast, no network call              | Can't detect revoked tokens; requires JWKS caching |
| **Remote (Introspection)** | POST to `/introspect`, AS responds with token state | Always current, detects revocation | Network round-trip on every request                |
| **Hybrid**                 | Local validation + periodic revocation check        | Balance of speed and freshness     | Complex to implement correctly                     |

For most deployments: use **local JWT validation** with short token lifetimes (15–60 min) to bound the revocation window. Implement introspection for high-assurance scenarios where immediate revocation is required.

---

## 8. End-to-End OIDC Exchange

A complete Authorization Code + PKCE + OIDC flow for a confidential web application.

**Setup:**

- IdP: `https://auth.example.com`
- RP: `https://myapp.com` (server-side, confidential client)
- `client_id`: `myapp-client-id`
- Requested scopes: `openid profile email offline_access`

---

### Step 1: Discovery (RP startup / cached)

```http
GET /.well-known/openid-configuration HTTP/1.1
Host: auth.example.com
```

RP extracts and caches `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `userinfo_endpoint`.

---

### Step 2: PKCE and Nonce Generation (RP, server-side)

```
code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
code_challenge = BASE64URL(SHA256(code_verifier))
             = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
state          = "xK9mP2qR7vL4nJ1w"
nonce          = "n-0S6_WzA2Mj"
```

RP stores `state`, `nonce`, and `code_verifier` in the user's server-side session (not in the browser).

---

### Step 3: Authorization Request

RP redirects the user's browser:

```http
GET /authorize?
  response_type=code
  &client_id=myapp-client-id
  &redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback
  &scope=openid%20profile%20email%20offline_access
  &state=xK9mP2qR7vL4nJ1w
  &nonce=n-0S6_WzA2Mj
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
  &prompt=login
  &max_age=86400
HTTP/1.1
Host: auth.example.com
```

> **Internal:** IdP records `code_challenge`, `nonce`, and session metadata. Displays login + consent UI.

---

### Step 4: User Authenticates and Consents

User enters credentials, completes MFA, clicks "Allow." IdP generates a short-lived authorization code.

---

### Step 5: Authorization Response

```http
HTTP/1.1 302 Found
Location: https://myapp.com/callback?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=xK9mP2qR7vL4nJ1w
```

> **RP Action:** Verify `state` matches session. Extract `code`.

---

### Step 6: Token Exchange

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic bXlhcHAtY2xpZW50LWlkOmNsaWVudC1zZWNyZXQ=

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https%3A%2F%2Fmyapp.com%2Fcallback
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

> **IdP Action:** Verifies `client_id`/`client_secret`. Recomputes `SHA256(code_verifier)` and compares to stored `code_challenge`. Match confirmed. Generates tokens.

---

### Step 7: Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InNpZ25pbmcta2V5LTIwMjQtMDEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWExYjJjM2Q0IiwiYXVkIjoiaHR0cHM6Ly9hcGkubXlhcHAuY29tIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsInNjb3BlIjoicHJvZmlsZSBlbWFpbCJ9.ACCESS_SIG",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "id_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InNpZ25pbmcta2V5LTIwMjQtMDEifQ.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLWExYjJjM2Q0IiwiYXVkIjoibXlhcHAtY2xpZW50LWlkIiwiZXhwIjoxNzAwMDAzNjAwLCJpYXQiOjE3MDAwMDAwMDAsImF1dGhfdGltZSI6MTY5OTk5OTgwMCwibm9uY2UiOiJuLTBTNl9XekEyTWoiLCJhdF9oYXNoIjoiTVRJek5EVTJOemM0T1RBeE1qTTAiLCJhY3IiOiJ1cm46bWFjZTppbmNvbW1vbjppYXA6c2lsdmVyIiwiYW1yIjpbInB3ZCIsIm1mYSJdLCJuYW1lIjoiU2hhaGVyeWFyIEFobWVkIiwiZW1haWwiOiJzaGFoZXJ5YXJAZXhhbXBsZS5jb20iLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZX0.ID_TOKEN_SIG",
  "scope": "openid profile email offline_access"
}
```

---

### Step 8: ID Token Validation (RP)

RP performs all checks from Section 7.1:

```
✓ Fetch JWKS from https://auth.example.com/jwks
✓ Select key with kid="signing-key-2024-01"
✓ Verify RS256 signature
✓ iss == "https://auth.example.com"  ✓
✓ aud == "myapp-client-id"  ✓
✓ exp (1700003600) > current_time (1700000060)  ✓
✓ nonce == "n-0S6_WzA2Mj" matches session  ✓  → invalidate stored nonce
✓ at_hash verified against access_token  ✓
✓ auth_time: 1699999800 — authenticated 200s ago, within max_age=86400  ✓
✓ acr: "silver" — MFA confirmed  ✓
→ Authentication successful. User identity: sub=user-a1b2c3d4
```

---

### Step 9: Optional UserInfo Call

```http
GET /userinfo HTTP/1.1
Host: auth.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN...
```

```json
{
  "sub": "user-a1b2c3d4",
  "name": "Shaheryar Ahmed",
  "given_name": "Shaheryar",
  "family_name": "Ahmed",
  "email": "shaheryar@example.com",
  "email_verified": true,
  "picture": "https://auth.example.com/users/user-a1b2c3d4/photo.jpg"
}
```

> **RP Action:** Verify `sub` matches ID Token `sub`. If mismatch → REJECT. Otherwise, use additional profile data.

---

## 9. Security Deep Dive

### 9.1 ID Token Replay Attacks (Nonce Misuse)

#### The Attack

An attacker captures a valid ID Token (from logs, from a compromised RP, or from a previous authentication). They inject this token into a new authentication session.

```
1. Victim authenticates → IdP issues ID Token with nonce="A"
2. Attacker captures the ID Token (e.g., from logs)
3. Attacker later initiates a new auth flow with the RP
4. Attacker intercepts the callback and substitutes the captured ID Token
5. If RP doesn't validate nonce, RP accepts the old token as fresh authentication
```

#### Impact

Authentication bypass. Attacker is logged in as the victim.

#### Mitigation

- Always generate and validate `nonce`
- The `nonce` in the ID Token must match the one generated for that specific authentication session
- Nonces must be single-use — invalidate after successful validation
- Nonces must be cryptographically random (not sequential or user-derived)

---

### 9.2 Improper ID Token Validation

#### The Attack

RPs that partially validate ID Tokens — or skip validation entirely when tokens are received from "trusted" sources — are vulnerable.

Common omissions:

- Skipping signature verification ("we got it from the HTTPS token endpoint, it must be safe")
- Not validating `aud` — token from one RP accepted by another
- Not validating `exp` — accepting expired tokens
- Not validating `nonce`

#### Impact

- Missing `aud` check → token issued for App A is accepted by App B (cross-site token confusion)
- Missing `exp` check → stolen tokens usable indefinitely
- Missing signature check → forged tokens accepted

#### Mitigation

Execute all 14 validation steps in Section 7.1. No exceptions. Use a well-tested OIDC library rather than hand-rolling validation. Libraries like `python-jose`, `nimbus-jose-jwt`, `jose` (Node.js) handle the full validation chain.

---

### 9.3 Signature Verification Bypass (`alg=none` and Algorithm Confusion)

#### Attack 1: `alg=none`

Some JWT libraries, if misconfigured, accept a token with `"alg": "none"` and no signature — treating it as valid:

```json
// Header
{ "alg": "none", "typ": "JWT" }
// Payload — any claims the attacker wants
{ "sub": "admin", "aud": "myapp-client-id", ... }
// Signature — empty string
```

This requires no cryptographic key. If the library accepts it, the attacker can forge any identity.

#### Attack 2: RS256 → HS256 Algorithm Confusion

Some libraries accept either RSA (asymmetric) or HMAC (symmetric) algorithms. An attacker:

1. Takes the IdP's **public RSA key** (publicly available in JWKS)
2. Signs a forged JWT using that public key as an **HMAC secret** with `alg=HS256`
3. Submits to an RP whose library uses the public key for both RS256 verification and HS256 verification without distinguishing

The library verifies the HMAC signature using the "public key" as the secret — and it matches, because the attacker used it to sign.

#### Impact

Complete authentication bypass. Attacker can forge any identity.

#### Mitigation

- **Hardcode the expected algorithm** in the RP's configuration — never accept `alg` from the token header without allowlisting
- Explicitly **reject `alg=none`**
- Use separate key material for HMAC and RSA operations
- Use well-maintained libraries with secure defaults (modern versions reject `none` by default)
- Configure: `allowed_algorithms = ["RS256", "ES256"]` — not `["RS256", "HS256", "none"]`

---

### 9.4 Key Confusion Attacks (JWKS Misuse)

#### The Attack

The RP fetches the wrong JWKS, uses the wrong key, or is tricked into trusting attacker-controlled keys.

Scenarios:

- **JWKS URL injection:** If the RP derives the JWKS URL from the `iss` claim in the token (rather than from the pre-configured discovery document), an attacker sets `"iss": "https://attacker.com"`, and the RP fetches keys from `https://attacker.com/jwks` — keys the attacker controls
- **kid confusion:** Multiple keys in JWKS — attacker crafts a token with a `kid` pointing to a key they control (if the JWKS is somehow tampered with)
- **Stale key cache attack:** The RP caches old keys indefinitely — a key compromise is not reflected

#### Mitigation

- **Never derive JWKS URL from the token** — always use the URL from the pre-configured or cached discovery document
- **Validate `iss` against the expected issuer before selecting a key** — not after
- Implement JWKS cache TTL and re-fetch on `kid` miss (but no more than once per request to prevent DoS)
- Pin the issuer URL — do not dynamically trust new issuers

---

### 9.5 Authorization Code Interception (OIDC Context)

Same mechanism as in OAuth 2.0, but with additional OIDC-specific consequences: the attacker who intercepts the code also receives the ID Token from the token endpoint, gaining the user's identity.

#### Mitigation

PKCE is the primary control. In OIDC specifically:

- `nonce` provides a secondary binding — even if the code is intercepted and exchanged, the attacker's session won't have the correct `nonce` in state to validate the returned ID Token
- This is why both PKCE and `nonce` should always be used together

---

### 9.6 Mix-Up Attacks

#### The Attack

The mix-up attack targets deployments where an RP supports **multiple IdPs**. An attacker operates a malicious IdP.

```
1. RP supports: auth.example.com (legitimate) and attacker.com (malicious)
2. User intends to authenticate with auth.example.com
3. Attacker intercepts the authorization request and redirects it to attacker.com
4. attacker.com completes a flow and issues an authorization code for attacker.com
5. The RP's callback receives a code — but doesn't know which IdP issued it
6. RP sends the code to auth.example.com's token endpoint (the legitimate one)
7. auth.example.com rejects the code — but the error reveals information
   OR: the RP confuses which IdP's token endpoint to use, sending the code to attacker.com
8. attacker.com issues a token for a victim user (whose code was obtained elsewhere)
```

#### Impact

Cross-IdP token confusion; in some scenarios, authentication as a different user.

#### Mitigation

- **Issuer binding:** The RP must track which IdP initiated each authentication session and validate that the callback is from the expected IdP

- **`iss` parameter in authorization response** (RFC 9207) — the authorization server includes its `issuer` in the authorization response, allowing the RP to verify the response came from the expected IdP:
  
  ```
  https://myapp.com/callback?code=...&state=...&iss=https%3A%2F%2Fauth.example.com
  ```

- Store the expected `iss` in the session alongside `state` and `nonce`

---

### 9.7 Token Substitution Attacks

#### The Attack

In flows that return multiple tokens (Hybrid Flow), an attacker substitutes a token from one flow into another.

Example: Attacker has a valid ID Token issued to them by the IdP. They substitute it into the callback for a victim's ongoing Hybrid Flow, tricking the RP into authenticating as the attacker rather than the victim.

#### Mitigation

- `c_hash` in the ID Token from the auth endpoint binds it to the specific authorization code — verify it
- `at_hash` binds the ID Token to the specific access token — verify it
- These hash bindings make substitution detectable: a substituted ID Token's `c_hash` won't match the victim's code

---

### 9.8 Confusion Between Access Token and ID Token

#### The Attack

A developer uses the access token as proof of identity (checking if it's valid and concluding they know who the user is), or sends the ID Token to an API as a Bearer token.

**Scenario A:** RP sends ID Token to Resource Server as Bearer token. RS is configured to accept any token from the IdP, validates the signature, and accepts it — but the `aud` check would fail (`aud` is the client ID, not the RS identifier). If the RS skips `aud` validation, it accepts tokens not intended for it.

**Scenario B:** RP trusts any valid access token as proof of user identity without verifying the ID Token, not checking `sub`, `nonce`, or `auth_time`.

#### Impact

In Scenario A: horizontal privilege escalation if RS accepts tokens from other clients.  
In Scenario B: authentication is reduced to "does a valid token exist" — bypassing user identity verification.

#### Mitigation

- ID Token → used exclusively by the RP to identify the user. Never forward to an API.
- Access Token → used exclusively to call APIs. Contains no reliable identity for the RP.
- Resource Servers must validate `aud` strictly — tokens intended for other audiences must be rejected.

---

### 9.9 Open Redirect Exploitation in OIDC

OIDC flows involve multiple redirects. Open redirect vulnerabilities can allow:

- Stealing authorization codes: redirect the callback to an attacker URL that captures the `code` parameter
- Stealing ID Tokens (Hybrid/Implicit): if `response_mode=fragment` or `response_mode=query`, tokens in the redirect URL go to the attacker

The attack surface is the `redirect_uri` parameter. If the IdP allows partial matching or wildcards, an attacker can direct the response to their server.

#### Mitigation

- Exact redirect URI matching (covered in OAuth 2.0 security section)
- In OIDC specifically: PKCE + `nonce` provide defense-in-depth — even if the code is delivered to the attacker, they can't exchange it (no `code_verifier`) and can't use the ID Token (no `nonce` match)

---

### 9.10 PKCE Misconfiguration in OIDC Flows

When PKCE is required but not enforced, or when `plain` method is allowed instead of `S256`:

- **No PKCE enforcement:** Authorization code can be exchanged by anyone who intercepts it — no `code_verifier` required. PKCE becomes theater.
- **`plain` method:** `code_challenge = code_verifier` — if an attacker intercepts the authorization request, they capture both the challenge (= verifier) and can use it in the token exchange.
- **Weak verifier entropy:** Predictable or short verifiers are brute-forceable within the code's short lifetime.

#### Mitigation

- IdP must enforce that if `code_challenge` was sent, `code_verifier` is required in the token exchange
- Only allow `S256` — remove `plain` from supported methods
- Minimum verifier length: 43 characters from a cryptographically secure random source
- Best practice: require PKCE for all flows, including confidential clients

---

## 10. Best Practices and Modern Recommendations

### 10.1 Flow Selection

```
User-facing authentication (web app, mobile, SPA):
  → Authorization Code + PKCE + OIDC
  → Always include nonce, state, code_challenge (S256)

Machine-to-machine (no user):
  → OAuth 2.0 Client Credentials
  → OIDC does not apply (no user to identify)

Input-constrained device:
  → Device Code Flow + OIDC
  → Include nonce in the device authorization request

NEVER use:
  → Implicit Flow
  → ROPC / Password Grant
  → Hybrid Flow (unless you have a specific architectural requirement)
```

### 10.2 ID Token Validation Checklist

```
□ Signature verified using IdP public key from JWKS
□ Algorithm is in the configured allowlist (not "none", not unexpected alg)
□ kid-based key selection (not try-all-keys)
□ iss exactly matches expected issuer from discovery document
□ aud contains client_id
□ exp > current_time (with ≤60s clock skew tolerance)
□ nonce matches session-stored value (if sent)
□ Nonce invalidated after use (single-use)
□ at_hash verified (if access_token received)
□ c_hash verified (if Hybrid Flow)
□ auth_time checked against max_age (if sent)
□ acr meets minimum requirement (if sent)
□ sub from UserInfo matches sub from ID Token
```

### 10.3 Secure Parameter Handling

| Parameter       | Requirement                                                                       |
| --------------- | --------------------------------------------------------------------------------- |
| `nonce`         | Cryptographically random, ≥128 bits, server-side storage, single-use              |
| `state`         | Cryptographically random, ≥128 bits, server-side storage                          |
| `code_verifier` | Cryptographically random, 43–128 chars, server-side only                          |
| `redirect_uri`  | Exact match against registered URIs; HTTPS only in production                     |
| `client_secret` | Never in URLs, JS code, or mobile binaries; server-side confidential clients only |

### 10.4 Token Storage

| Token         | Storage Location                       | Never Store In                      |
| ------------- | -------------------------------------- | ----------------------------------- |
| Access Token  | Memory (SPA), HttpOnly cookie (server) | localStorage, sessionStorage, URL   |
| Refresh Token | Server-side session, HttpOnly cookie   | localStorage, JS-accessible storage |
| ID Token      | Server-side session (after validation) | localStorage, URL, client-side JS   |

### 10.5 Scope and Claims Minimization

- Request only the scopes needed for the immediate operation (incremental authorization)
- Do not request `profile` if you only need `sub` and `email`
- Use `offline_access` only when the application genuinely needs background access
- Configure the IdP to issue minimal claims in ID Tokens; use UserInfo for supplemental data
- Custom claims with sensitive data should be in encrypted ID Tokens (JWE) if they must be in the token

### 10.6 Session Management and Logout

OIDC defines three logout mechanisms:

| Mechanism                | How It Works                                                | When To Use                                                |
| ------------------------ | ----------------------------------------------------------- | ---------------------------------------------------------- |
| **RP-Initiated Logout**  | RP redirects user to IdP's `end_session_endpoint`           | When user explicitly logs out                              |
| **Front-Channel Logout** | IdP loads RPs' logout URLs in iframes                       | When IdP needs to log out user from all RPs simultaneously |
| **Back-Channel Logout**  | IdP POSTs a signed logout token to each RP's registered URL | Most reliable; not browser-dependent; preferred            |

Back-channel logout is the modern recommendation. The logout token is a signed JWT (similar to an ID Token) containing `sub` and `sid`, allowing the RP to invalidate the corresponding session server-side without user browser involvement.

### 10.7 Library and Implementation Guidance

Do not implement OIDC validation from scratch in production. Use audited libraries:

| Language | Recommended Library                       |
| -------- | ----------------------------------------- |
| Python   | `authlib`, `python-jose`, `oic`           |
| Node.js  | `openid-client`, `jose`                   |
| Java     | `nimbus-jose-jwt`, Spring Security OAuth2 |
| .NET     | `Microsoft.Identity.Web`, `IdentityModel` |
| Go       | `coreos/go-oidc`                          |

When evaluating a library, verify it:

- Rejects `alg=none`
- Validates `iss`, `aud`, `exp`, `nonce` by default
- Uses `kid`-based key selection
- Supports automatic JWKS refresh

---

## Quick Reference

```
OIDC EXTENDS OAUTH 2.0 BY ADDING:
  openid scope      → triggers OIDC
  id_token          → JWT asserting user identity
  nonce parameter   → ID Token replay protection
  UserInfo endpoint → additional identity claims
  Discovery doc     → self-configuring trust model

ID TOKEN REQUIRED CLAIMS:
  iss  sub  aud  exp  iat
  + nonce (if sent)  + auth_time (if max_age sent)

ID TOKEN CRITICAL VALIDATION:
  1. Signature (RS256/ES256, using JWKS)
  2. iss == expected issuer
  3. aud ∋ client_id
  4. exp > now
  5. nonce == session nonce (invalidate after)
  6. at_hash matches access_token

KEY SECURITY RULES:
  → Never accept alg=none
  → Never derive JWKS URL from token claims
  → Never use ID Token as Bearer token to APIs
  → Never use access token as proof of identity
  → Always validate nonce
  → Always use PKCE + S256
  → Always validate ALL 14 steps — no shortcuts
```

---

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Connect RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html)
- [OpenID Connect Back-Channel Logout](https://openid.net/specs/openid-connect-backchannel-1_0.html)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7517 — JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [RFC 9207 — OAuth 2.0 Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [OAuth 2.0 Security BCP](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP Testing for OAuth/OIDC Weaknesses](https://owasp.org/www-project-web-security-testing-guide/)
- [PortSwigger — OAuth 2.0 Authentication Vulnerabilities](https://portswigger.net/web-security/oauth)
- [jwt.io — JWT Debugger](https://jwt.io)
