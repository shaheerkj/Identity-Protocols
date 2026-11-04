# OAuth 2.0: A Comprehensive Technical Reference

> **Audience:** Security practitioners, cloud engineers, and developers studying IAM, SC-200, or modern authentication protocols.  
> **Goal:** After reading this document, you should be able to explain OAuth 2.0 end-to-end, implement it securely, identify attack vectors, and make informed design decisions.

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Core Components](#2-core-components)
3. [OAuth 2.0 Flows (Grant Types)](#3-oauth-20-flows-grant-types)
4. [Protocol Internals](#4-protocol-internals)
5. [End-to-End Example](#5-end-to-end-example)
6. [Practical Exercises](#6-practical-exercises)
7. [Security Deep Dive](#7-security-deep-dive)
8. [Best Practices](#8-best-practices)

---

## 1. Introduction

### 1.1 What Is OAuth 2.0?

OAuth 2.0 is an **authorization framework** defined in [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749). It enables a third-party application to obtain **limited access** to a service on behalf of a user — without ever seeing that user's credentials.

The key word is **authorization** (what you're allowed to do), not authentication (who you are). OAuth 2.0 does not, by itself, tell an application who the user is — that's the job of **OpenID Connect (OIDC)**, which is a thin identity layer built on top of OAuth 2.0.

### 1.2 Why Does OAuth 2.0 Exist?

#### The Problem: Credential Sharing

Before OAuth, if you wanted App A to access your data on Service B (e.g., a photo printing service accessing your Google Photos), the only option was to **give App A your Google username and password**.

This is catastrophically insecure:

- App A now has full access to your Google account — not just photos
- You cannot revoke access without changing your password (which affects all apps)
- App A could store, leak, or misuse your credentials
- If App A is breached, your Google account is compromised

#### The Solution: Delegated Authorization

OAuth 2.0 replaces credential sharing with **tokens**. Instead of your password, App A receives a short-lived, scoped **access token** that only grants access to what you explicitly approved (e.g., read-only access to photos).

```textile
WITHOUT OAuth:   User → gives password to App → App acts as User (unlimited access)
WITH OAuth:      User → approves limited scope → Auth Server issues token → App uses token (scoped access)
```

### 1.3 Authorization vs. Authentication

This distinction is critical and frequently confused:

| Concept            | Question Answered           | Protocol                    |
| ------------------ | --------------------------- | --------------------------- |
| **Authentication** | Who are you?                | OpenID Connect (OIDC), SAML |
| **Authorization**  | What are you allowed to do? | OAuth 2.0                   |

OAuth 2.0 answers: *"Is this token allowed to read the user's calendar?"*  
OIDC answers: *"Which user does this token belong to?"*

> **Important:** OAuth 2.0 access tokens are **not proof of identity**. Never use the presence of a valid access token to conclude you know *who* the user is.

### 1.4 Real-World Use Cases

- **"Login with Google" / "Login with GitHub"** — Technically OpenID Connect (OAuth 2.0 + identity layer)
- **Spotify accessing your Facebook friends list** — Classic OAuth 2.0 delegated authorization
- **A CI/CD pipeline pushing to GitHub** — Client Credentials Flow (no user involved)
- **Smart TV apps** — Device Code Flow (limited input capability)
- **Microsoft 365 integrations** — Azure AD as the Authorization Server, various flows depending on client type

---

## 2. Core Components

### 2.1 Resource Owner

The **Resource Owner** is the entity that owns the data or resource being accessed — almost always a **human user**.

When you click "Allow" on a permission consent screen, you are acting as the Resource Owner, granting permission to a third-party application to access your data.

### 2.2 Client

The **Client** is the application requesting access to a protected resource on behalf of the Resource Owner. Clients come in two types based on their ability to keep secrets:

#### Confidential Clients

Can securely store a `client_secret` (a password for the application itself). These run on servers the developer controls.

- **Examples:** Backend web servers, server-side APIs, daemon services
- **Can use:** Authorization Code Flow, Client Credentials Flow
- **Key characteristic:** The `client_secret` never leaves the server

#### Public Clients

Cannot securely store secrets because the code is exposed to the user's device or environment.

- **Examples:** Single Page Applications (SPAs), mobile apps, desktop apps
- **Cannot use:** Flows requiring `client_secret`
- **Must use:** PKCE (Proof Key for Code Exchange) to compensate
- **Key characteristic:** Any secret embedded in the code can be extracted

### 2.3 Authorization Server (AS)

The **Authorization Server** is the trusted party that:

1. Authenticates the Resource Owner (the user logs in here)
2. Presents the consent screen
3. Issues tokens (access tokens, refresh tokens, ID tokens)
4. Validates token requests

Examples: Google Identity Platform, Microsoft Entra ID (Azure AD), Okta, Auth0, Keycloak.

Key endpoints exposed by the AS:

- `GET /authorize` — starts the authorization flow
- `POST /token` — exchanges codes/credentials for tokens
- `GET /.well-known/openid-configuration` — discovery document

### 2.4 Resource Server (RS)

The **Resource Server** hosts the protected resources (APIs, data). It:

1. Accepts requests containing access tokens (usually in the `Authorization: Bearer <token>` header)
2. Validates the token (checks signature, expiry, scope)
3. Returns the resource if the token is valid and has the right scope

The Resource Server and Authorization Server are often operated by the same company but are logically separate components.

### 2.5 Tokens

#### Access Token

- Short-lived credential that grants access to specific resources
- Typically expires in **15 minutes to 1 hour**
- Sent with every API request: `Authorization: Bearer <token>`
- Should be treated like a password — never log it, never expose it in URLs

#### Refresh Token

- Long-lived credential used to obtain new access tokens without re-authenticating
- Expires in **days to weeks** (or never, depending on configuration)
- Stored securely (httpOnly cookie or secure server-side storage)
- Can be **revoked** by the Authorization Server
- Only issued in flows where the user is present (not Client Credentials)

#### ID Token (OIDC)

- A **JWT (JSON Web Token)** containing claims about the authenticated user
- Only issued when the `openid` scope is requested
- Not intended to be sent to APIs — it's for the **client application** to learn about the user
- Contains: `sub` (user ID), `email`, `name`, `iat` (issued at), `exp` (expiry), `iss` (issuer), `aud` (audience)

---

## 3. OAuth 2.0 Flows (Grant Types)

Different scenarios require different flows. The right flow depends on:

- Who/what is the client? (user present? server-side? IoT device?)
- Can the client keep a secret?
- What level of trust is acceptable?

---

### 3.1 Authorization Code Flow

**Best for:** Confidential clients (server-side web apps) with a user present.

This is the **most secure and widely used** flow. It never exposes tokens in the browser URL bar.

#### How It Works (Step by Step)

```text
```text
User          Browser/Client          Authorization Server          Resource Server
  |                  |                         |                          |
  |-- clicks login -->|                         |                          |
  |                  |-- GET /authorize ------->|                          |
  |                  |                         |                          |
  |<--- redirected to AS login page -----------|                          |
  |-- enters credentials --------------------->|                          |
  |<--- consent screen shown ------------------|                          |
  |-- approves ------------------------------->|                          |
  |                  |<-- redirect with code ---|                          |
  |                  |                         |                          |
  |                  |-- POST /token (code) --->|                          |
  |                  |<-- access_token,        |                          |
  |                  |    refresh_token -------|                          |
  |                  |                         |                          |
  |                  |-- API request + Bearer token ---------------------->|
  |                  |<-- protected resource --------------------------------|
```

```
#### Step 1: Authorization Request

The client redirects the user's browser to the AS:

```http
GET /authorize?
  response_type=code
  &client_id=myapp-client-id
  &redirect_uri=https://myapp.com/callback
  &scope=read:profile read:email
  &state=xK9mP2qR7vL4nJ1w
HTTP/1.1
Host: auth.example.com
```

| Parameter            | Purpose                                         |
| -------------------- | ----------------------------------------------- |
| `response_type=code` | Tells AS to return an authorization code        |
| `client_id`          | Identifies the application                      |
| `redirect_uri`       | Where to send the user after authorization      |
| `scope`              | What permissions are being requested            |
| `state`              | Random value for CSRF protection — **critical** |

#### Step 2: Authorization Response

After the user logs in and approves, the AS redirects back:

```http
HTTP/1.1 302 Found
Location: https://myapp.com/callback?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=xK9mP2qR7vL4nJ1w
```

The `code` is short-lived (typically **60 seconds**) and single-use.

> One thing I really thought about here was: *Why don't we just return the access token here instead of auth code? Seemed redundant.* (AS) does **not give the access token directly to the browser** because the browser is a **high-risk environment**.

#### Step 3: Token Exchange

The server-side client exchanges the code for tokens — this is a **back-channel** request (browser never sees it):

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://myapp.com/callback
```

#### Step 4: Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "scope": "read:profile read:email"
}
```

This token is a **Bearer token**, and whoever *holds it* can use it to access the resource server

---

### 3.2 Authorization Code Flow with PKCE

**Best for:** Public clients (SPAs, mobile apps) where a `client_secret` cannot be kept safe.

PKCE (Proof Key for Code Exchange, pronounced "pixie") — defined in [RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636) — adds a cryptographic challenge to the Authorization Code Flow, preventing code interception attacks.

#### How PKCE Works

Before starting the flow, the client:

1. Generates a random **code_verifier** (43–128 character random string)
2. Computes: `code_challenge = BASE64URL(SHA256(code_verifier))`
3. Sends `code_challenge` with the authorization request
4. Sends `code_verifier` with the token request (proves it made the original request)

Even if an attacker intercepts the authorization code, they cannot use it without the `code_verifier`, which was never sent over the network in plaintext.

#### Step 1: Generate PKCE Values

```javascript
// Generate a cryptographically random code_verifier
const code_verifier = base64url(crypto.getRandomValues(new Uint8Array(32)));

// Compute code_challenge
const code_challenge = base64url(await crypto.subtle.digest(
  'SHA-256',
  new TextEncoder().encode(code_verifier)
));
```

#### Step 2: Authorization Request (with PKCE)

```http
GET /authorize?
  response_type=code
  &client_id=myapp-spa-client
  &redirect_uri=https://myapp.com/callback
  &scope=read:profile
  &state=xK9mP2qR7vL4nJ1w
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
HTTP/1.1
Host: auth.example.com
```

#### Step 3: Token Exchange (with PKCE)

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://myapp.com/callback
&client_id=myapp-spa-client
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

> Note: No `client_secret` — the `code_verifier` serves as proof of ownership.

The AS recomputes `SHA256(code_verifier)` and compares it to the stored `code_challenge`. If they match, it issues tokens.

This flow describes it properly, where client is our server side application.

```
+--------+          +----------+          +--------------------+          +--------+
|  User  |          | Browser  |          | Client (SP)        |          |  Auth  |
|        |          |          |          |                    |          | Server |
+--------+          +----------+          +--------------------+          +--------+
    |                    |                          |                         |
    | clicks login       |                          |                         |
    |------------------->|                          |                         |
    |                    | GET /login               |                         |
    |                    |------------------------->|                         |
    |                    |                          |                         |
    |                    |                          | gen code_verifier       |
    |                    |                          | gen code_challenge      |
    |                    |                          | = BASE64URL(SHA256(v))  |
    |                    |                          | gen state               |
    |                    |                          |                         |
    |                    |    302 → /authorize      |                         |
    |                    |  ?response_type=code     |                         |
    |                    |  &code_challenge=...     |                         |
    |                    |  &code_challenge_method  |                         |
    |                    |  =S256 &state=...        |                         |
    |                    |<-------------------------|                         |
    |                    |                                                    |
    |                    | GET /authorize?code_challenge=...&state=...        |
    |                    |--------------------------------------------------->|
    |                    |                                                    |
    |                    |              login + consent UI                    |
    |                    |<---------------------------------------------------|
    | enter credentials  |                                                    |
    |  & approve         |                                                    |
    |------------------->|                                                    |
    |                    | credentials                                        |
    |                    |--------------------------------------------------->|
    |                    |                          |                         |
    |                    |                          |          store          |
    |                    |                          |       code_challenge    |
    |                    |                          |       against code      |
    |                    |                          |                         |
    |                    | 302 → /callback?code=AUTH_CODE&state=...           |
    |                    |<---------------------------------------------------|
    |                    | GET /callback?code=AUTH_CODE&state=...             |
    |                    |------------------------->|                         |
    |                    |                          | verify state ✓          |
    |                    |                          |                         |
    |                    |                          | POST /token             |
    |                    |                          | grant_type=auth_code    |
    |                    |                          | &code=AUTH_CODE         |
    |                    |                          | &code_verifier=...      |
    |                    |                          |------------------------>|
    |                    |                          |                         |
    |                    |                          |    SHA256(verifier)     |
    |                    |                          |    == code_challenge? ✓ |
    |                    |                          |                         |
    |                    |                          |   access_token          |
    |                    |                          |   id_token              |
    |                    |                          |   refresh_token         |
    |                    |                          |<------------------------|
    |                    |    set session cookie    |                         |
    |                    |<-------------------------|                         |
    | authenticated ✓    |                          |                         |
    |<-------------------|                          |                         |
```

---

### 3.3 Client Credentials Flow

**Best for:** Machine-to-machine (M2M) communication with **no user involved**.

Used by: microservices, background jobs, CI/CD pipelines, daemons.

#### How It Works

```
Client (Service)          Authorization Server          Resource Server
      |                          |                           |
      |-- POST /token ---------->|                           |
      |   (client_id +           |                           |
      |    client_secret)        |                           |
      |<-- access_token ---------|                           |
      |                          |                           |
      |-- API request + Bearer token ----------------------->|
      |<-- protected resource --------------------------------|
```

#### Token Request

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=client_credentials
&scope=reports:read metrics:write
```

#### Token Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "reports:read metrics:write"
}
```

> No `refresh_token` is issued — the client simply requests a new access token when needed.

---

### 3.4 Device Code Flow

**Best for:** Devices with limited input capability (smart TVs, IoT devices, CLI tools, gaming consoles).

The device cannot open a browser or accept keyboard input, so authentication is delegated to another device (e.g., a phone or laptop).

#### How It Works

```
Device                    Auth Server                  User's Phone/Browser
  |                           |                                |
  |-- POST /device_code ----->|                                |
  |<-- device_code,           |                                |
  |    user_code,             |                                |
  |    verification_uri ------|                                |
  |                           |                                |
  |-- display user_code ------|-------- user visits URI ------>|
  |                           |<------- enters user_code ------|
  |                           |<------- user approves ---------|
  |                           |                                |
  |-- poll POST /token ------>|                                |
  |<-- access_token ----------|                                |
```

#### Step 1: Device Authorization Request

```http
POST /device_authorization HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

client_id=device-client-id
&scope=read:profile
```

#### Step 2: Device Authorization Response

```json
{
  "device_code": "GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "WDJB-MJHT",
  "verification_uri": "https://auth.example.com/device",
  "verification_uri_complete": "https://auth.example.com/device?user_code=WDJB-MJHT",
  "expires_in": 900,
  "interval": 5
}
```

The device displays: *"Go to auth.example.com/device and enter code: WDJB-MJHT"*

#### Step 3: Polling for the Token

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code
&device_code=GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS
&client_id=device-client-id
```

While the user hasn't approved yet, the AS responds:

```json
{ "error": "authorization_pending" }
```

Once the user approves, the next poll returns:

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8"
}
```

---

### 3.5 Refresh Token Flow

Access tokens expire. Rather than forcing the user to re-authenticate, the client uses a **refresh token** to get a new access token silently.

#### Token Refresh Request

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded
Authorization: Basic base64(client_id:client_secret)

grant_type=refresh_token
&refresh_token=8xLOxBtZp8
```

#### Token Refresh Response

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9.NEW...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "9yMPxCuAq9"
}
```

> Some AS implementations use **refresh token rotation** — each refresh issues a new refresh token and invalidates the old one. This limits the damage if a refresh token is stolen.

---

### 3.6 Deprecated Flows (Avoid These)

#### Implicit Flow (DEPRECATED)

The Authorization Server returned the access token **directly in the URL fragment** after user approval:

```
https://myapp.com/callback#access_token=eyJ...&expires_in=3600
```

**Why it's dangerous and deprecated:**

- Access token appears in the browser URL bar — visible in browser history, server logs, and `Referer` headers
- No `state` parameter verification was common, enabling CSRF
- No refresh token support
- Replaced entirely by **Authorization Code + PKCE** for public clients

#### Resource Owner Password Credentials (ROPC) (DEPRECATED)

The user gives their username and password **directly to the client application**, which passes them to the AS.

```http
POST /token
grant_type=password&username=user@example.com&password=hunter2&client_id=...
```

**Why it's dangerous:**

- Completely defeats the purpose of OAuth (the client sees credentials)
- No consent screen or scoped access
- Only ever acceptable for first-party apps during migration — even then, avoid it

---

## 4. Protocol Internals

### 4.1 Key Endpoints

#### `/authorize` (GET)

Starts user-facing authorization. Browser redirects here.

```
GET https://auth.example.com/authorize?response_type=code&client_id=...&...
```

This is where the user logs in and sees the consent screen.

#### `/token` (POST)

Back-channel token issuance. Called by the client application directly (not browser redirect).

```
POST https://auth.example.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=...&...
```

#### `/.well-known/openid-configuration` (GET)

OIDC Discovery Document — a JSON document listing all AS endpoints, supported scopes, signing algorithms, etc. Use this to configure OAuth clients dynamically.

```bash
curl https://accounts.google.com/.well-known/openid-configuration
```

### 4.2 Key Parameters

| Parameter        | Where Used                            | Purpose                                                  |
| ---------------- | ------------------------------------- | -------------------------------------------------------- |
| `client_id`      | All requests                          | Identifies the application                               |
| `client_secret`  | Token requests (confidential clients) | Authenticates the application                            |
| `redirect_uri`   | Auth request, token request           | Where to return the user; must match registered value    |
| `response_type`  | Auth request                          | `code` for Authorization Code flow                       |
| `scope`          | Auth request                          | Permissions being requested (space-separated)            |
| `state`          | Auth request, response                | CSRF protection — random, opaque, verified on return     |
| `code`           | Auth response, token request          | Short-lived authorization code                           |
| `grant_type`     | Token request                         | The flow being used                                      |
| `code_verifier`  | Token request (PKCE)                  | Proves the client made the original auth request         |
| `code_challenge` | Auth request (PKCE)                   | Hash of the code_verifier                                |
| `nonce`          | Auth request (OIDC)                   | Binds ID token to specific auth session, prevents replay |

### 4.3 Scopes and Consent

Scopes are **string identifiers** representing permissions. There is no universal standard for scope names (except OIDC scopes like `openid`, `profile`, `email`).

Examples:

```
openid profile email          # OIDC identity scopes
read:repositories             # GitHub
https://www.googleapis.com/auth/gmail.readonly   # Google (URL-style scopes)
user.read Mail.ReadWrite      # Microsoft Graph
```

The consent screen shown to users maps scopes to human-readable descriptions. Requesting minimal, specific scopes is a security best practice (**principle of least privilege**).

### 4.4 Token Formats

#### Opaque Tokens

- A random string with no inherent meaning
- The Resource Server must call the AS's **introspection endpoint** (`/introspect`) to validate
- Allows the AS to revoke tokens instantly
- More network overhead

```bash
# Introspection request
POST /introspect
Authorization: Basic base64(rs_client_id:rs_secret)
token=random_opaque_token_string
```

#### JWT (JSON Web Token)

Defined in [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519). Self-contained: the Resource Server can validate without calling the AS.

Structure: `header.payload.signature` (each Base64URL encoded)

**Header:**

```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-1"
}
```

**Payload (Claims):**

```json
{
  "iss": "https://auth.example.com",
  "sub": "user-12345",
  "aud": "https://api.example.com",
  "exp": 1700000000,
  "iat": 1699996400,
  "jti": "unique-token-id",
  "scope": "read:profile read:email"
}
```

**Signature:**

```
RSA_SHA256(
  base64url(header) + "." + base64url(payload),
  private_key
)
```

### 4.5 Token Validation (JWT)

A Resource Server validating a JWT must check:

1. **Signature** — Verify using the AS's public key (fetched from `/jwks` endpoint)
2. **`iss` (issuer)** — Must match the expected Authorization Server
3. **`aud` (audience)** — Must include this Resource Server's identifier
4. **`exp` (expiry)** — Current time must be before expiry
5. **`iat` (issued at)** — Should not be too far in the past
6. **`scope`** — Token must contain the required scope for the requested operation
7. **`jti` (JWT ID)** — Optionally check against a blocklist for replay prevention

---

## 5. End-to-End Example

A complete Authorization Code + PKCE flow for a Single Page Application calling a GitHub-style API.

### Setup

- **Client:** Single Page Application at `https://myapp.com`
- **Authorization Server:** `https://auth.example.com`
- **Resource Server:** `https://api.example.com`
- **Requested scope:** `repo:read user:profile`

---

### Step 1: User Clicks "Connect Account"

The SPA generates PKCE values:

```
code_verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
code_challenge = BASE64URL(SHA256(code_verifier))
             = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
state          = "abc123xyz789"   ← stored in sessionStorage
```

**Browser is redirected to:**

```http
GET /authorize?
  response_type=code
  &client_id=spa-client-001
  &redirect_uri=https://myapp.com/callback
  &scope=repo:read%20user:profile
  &state=abc123xyz789
  &code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
  &code_challenge_method=S256
HTTP/1.1
Host: auth.example.com
```

> **What happens:** AS presents login page and consent screen to user.

---

### Step 2: User Authenticates and Approves

After the user logs in and clicks "Allow," the AS redirects back to the SPA:

```http
HTTP/1.1 302 Found
Location: https://myapp.com/callback?
  code=SplxlOBeZQQYbYS6WxSbIA
  &state=abc123xyz789
```

**SPA verifies:** `state` in the redirect matches `state` stored in sessionStorage.

> **What happens:** SPA now has an authorization code. This code is useless to an attacker without the `code_verifier`.

---

### Step 3: SPA Exchanges Code for Tokens

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=SplxlOBeZQQYbYS6WxSbIA
&redirect_uri=https://myapp.com/callback
&client_id=spa-client-001
&code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
```

> **What the AS does:** Recomputes `SHA256(code_verifier)`, compares to stored `code_challenge`. Match → issues tokens.

**Response:**

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyLTEyMzQ1IiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20iLCJleHAiOjE3MDAwMDAzNjAsImlhdCI6MTcwMDAwMDAwMCwic2NvcGUiOiJyZXBvOnJlYWQgdXNlcjpwcm9maWxlIn0.SIGNATURE",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "8xLOxBtZp8",
  "scope": "repo:read user:profile"
}
```

---

### Step 4: SPA Calls the API

```http
GET /user/profile HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xIn0...
```

> **What the RS does:** Validates JWT signature, checks `iss`, `aud`, `exp`, `scope`. All valid → returns data.

**Response:**

```json
{
  "id": "user-12345",
  "username": "shaheryar",
  "email": "shaheryar@example.com",
  "repos": [...]
}
```

---

### Step 5: Access Token Expires — SPA Refreshes

One hour later, the API returns `401 Unauthorized`. The SPA uses the refresh token:

```http
POST /token HTTP/1.1
Host: auth.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=8xLOxBtZp8
&client_id=spa-client-001
```

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiJ9.NEW_TOKEN...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "9yMPxCuAq9"
}
```

The user never had to log in again.

---

## 6. Practical Exercises

### Exercise 1: Craft an Authorization Request in the Browser

Use Google's OAuth 2.0 Playground or construct this URL manually and open it:

```
https://accounts.google.com/o/oauth2/v2/auth?
  response_type=code
  &client_id=YOUR_CLIENT_ID
  &redirect_uri=https://oauth2.example.com/code
  &scope=openid%20email%20profile
  &state=random_state_value_here
  &access_type=offline
```

**Observe:**

- The Google login/consent screen
- The `code` parameter in the redirect URL after approval
- The `state` value echoed back

---

### Exercise 2: Exchange a Code for a Token Using curl

```bash
curl -X POST https://oauth2.googleapis.com/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=YOUR_AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=https://oauth2.example.com/code"
```

**Or with PowerShell:**

```powershell
$body = @{
    grant_type    = "authorization_code"
    code          = "YOUR_AUTHORIZATION_CODE"
    client_id     = "YOUR_CLIENT_ID"
    client_secret = "YOUR_CLIENT_SECRET"
    redirect_uri  = "https://oauth2.example.com/code"
}

Invoke-RestMethod -Method Post `
    -Uri "https://oauth2.googleapis.com/token" `
    -Body $body
```

---

### Exercise 3: Decode and Inspect a JWT

Take any JWT (e.g., the `access_token` from the above exercise) and decode it. Use [jwt.io](https://jwt.io) in the browser, or via CLI:

```bash
# Split JWT by "." and decode each part
TOKEN="eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMzQ1In0.SIGNATURE"

# Decode header
echo $TOKEN | cut -d. -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Decode payload
echo $TOKEN | cut -d. -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Identify:**

- `iss` — who issued the token
- `aud` — who the token is for
- `exp` — when it expires (Unix timestamp → `date -d @TIMESTAMP`)
- `scope` — what permissions it grants

> **Note:** You can decode the header and payload without any keys — they're just Base64. The signature is what you need the public key to verify.

---

### Exercise 4: Identify Parameters in a Real OAuth Request

Capture an OAuth flow using browser DevTools (Network tab) when logging in with Google on any site. Find and identify:

- [ ] The `GET /authorize` request and all query parameters
- [ ] The `state` value sent and returned
- [ ] The `scope` being requested
- [ ] The `redirect_uri` — does it match exactly?
- [ ] The `POST /token` request (may be hidden — it's server-side)
- [ ] Whether PKCE parameters are present (`code_challenge`, `code_challenge_method`)

---

## 7. Security Deep Dive

This section covers OAuth 2.0 attack vectors, how they work, and how to prevent them. Understanding these is essential for SC-200 and IAM security roles.

---

### 7.1 Authorization Code Interception

#### The Attack

An attacker intercepts the authorization code from the redirect URL before the legitimate client receives it. This can happen via:

- Malicious apps on a mobile device registered to handle the same URI scheme
- Compromised browser extensions
- Network interception if redirect URI uses HTTP

**Attack scenario:**

```
1. User approves consent on legitimate app
2. AS redirects: myapp://callback?code=STOLEN_CODE
3. Attacker's malicious app intercepts the redirect (registered same URI)
4. Attacker sends STOLEN_CODE to AS /token endpoint
5. Attacker receives valid access token
```

#### Mitigation

**PKCE** — Even with the code, the attacker cannot exchange it for a token without the `code_verifier` that was never sent over the network unencrypted. Always use PKCE for public clients.

---

### 7.2 Missing or Weak `state` Parameter (CSRF)

#### The Attack

If the `state` parameter is absent or not validated, the flow is vulnerable to Cross-Site Request Forgery.

```
1. Attacker begins an OAuth flow and gets a valid authorization URL
2. Attacker sends victim a link that completes the attacker's authorization
3. Victim's browser sends the attacker's authorization code to the victim's logged-in session
4. Victim's account is now linked to attacker's external account
5. Attacker can now authenticate as victim
```

This is called an **OAuth CSRF** or **account linking attack**.

#### Mitigation

- Always generate a **cryptographically random** `state` value per authorization request
- Store it server-side or in a secure, HttpOnly cookie
- **Reject any callback where `state` doesn't match the stored value**
- Never use predictable values (`state=1`, `state=userid`)

---

### 7.3 Open Redirect Abuse

#### The Attack

If the AS doesn't strictly validate `redirect_uri`, an attacker can steal the authorization code by redirecting it to a URL they control:

```
Attacker crafts:
GET /authorize?client_id=legit-app&redirect_uri=https://attacker.com/steal&...

If AS allows partial/prefix matching:
→ Auth code is delivered to attacker.com
```

Partial matching is the key vulnerability: if the AS checks only that the `redirect_uri` *starts with* the registered domain, `https://legit.com.evil.com` would pass.

#### Mitigation

- **Exact string matching** of `redirect_uri` against pre-registered values — no wildcards, no prefix matching
- Require redirect URIs to be registered explicitly at client registration
- The AS should reject any mismatch with an error (not silently redirect)

---

### 7.4 Token Leakage

#### The Attack

Access tokens exposed in:

- **URL query strings** — appear in browser history, server access logs, proxy logs, and `Referer` headers (`?access_token=eyJ...`)
- **Browser history** — Implicit Flow's fatal flaw
- **Log files** — if tokens are logged in application logs
- **Referer headers** — when navigating from a page with a token in the URL

#### Mitigation

- **Never** put tokens in URL query parameters
- Use `Authorization: Bearer <token>` header exclusively
- Set `Referrer-Policy: no-referrer` on pages that handle tokens
- Ensure tokens are excluded from application and infrastructure logging
- Use short token lifetimes to limit the window of exposure

---

### 7.5 PKCE Bypass and Misuse

#### The Attack

1. **No PKCE enforcement:** AS accepts token requests without `code_verifier` even when PKCE was used in the auth request → PKCE is decorative
2. **`code_challenge_method=plain`:** Using the verifier as the challenge directly — if an attacker can intercept the auth request, they get the verifier
3. **Weak code_verifier:** Using a short or low-entropy verifier — vulnerable to brute force

#### Mitigation

- AS must **require** `code_verifier` if `code_challenge` was sent
- **Only allow `S256`** as `code_challenge_method` — reject `plain`
- Enforce minimum code_verifier length (43 characters) and cryptographic randomness
- PKCE should be required for all public clients and recommended for confidential clients too

---

### 7.6 Improper Redirect URI Validation

Already partly covered in Open Redirect, but includes additional vectors:

- **Subdomain matching:** Allowing `*.example.com` — attacker registers `evil.example.com`
- **Path traversal:** `https://legit.com/path/../../../` tricks
- **Localhost exceptions:** Some AS implementations allow any localhost port — attackers run a local service to catch redirects
- **HTTP vs HTTPS:** Allowing HTTP redirect URIs in production

#### Mitigation

- Exact string comparison only
- All production redirect URIs must use HTTPS
- Reject loopback (localhost) URIs in production except for native app flows with specific protections

---

### 7.7 Scope Over-Permission

#### The Attack

- Applications requesting `*` or `admin` scopes when they only need read access
- Users blindly approving broad scopes they don't understand
- If the application is compromised, the attacker has access to far more than necessary

#### Mitigation

- Request **minimum necessary scopes** for the specific operation
- Implement **incremental authorization** — request additional scopes only when needed
- AS should present clear, human-readable descriptions of each scope
- Resource Server should verify the **specific scope** required for each endpoint, not just "is the token valid?"

---

### 7.8 Token Replay Attacks

#### The Attack

If an attacker obtains a valid access token (via leakage, network interception, etc.), they can replay it against the Resource Server for the duration of its lifetime.

#### Mitigation

- **Short token lifetimes** (15–60 minutes) limit the replay window
- **`jti` (JWT ID) tracking** — maintain a blocklist of used JTIs on the Resource Server
- **Sender-constrained tokens** — Mutual TLS (mTLS) or DPoP (Demonstrating Proof of Possession) bind tokens to the client's cryptographic key, making stolen tokens useless without the private key
- **Token revocation** — AS implements a revocation endpoint; Resource Servers check it or use short lifetimes

---

### 7.9 Real-World Attack Scenario: Account Takeover via OAuth

**Setup:** A web app lets users "Login with Google." The app links a Google account to a local account by matching email addresses.

**Attack:**

```
1. Attacker knows victim's email: victim@gmail.com
2. Attacker creates a Google account with victim@gmail.com (or controls one)
3. Attacker completes OAuth login on the target app using their Google account
4. Target app sees email=victim@gmail.com and logs attacker into victim's account
```

**Root cause:** Trusting email from an OAuth provider without verifying it's been confirmed by that provider, or not checking the `sub` (user ID) which is unique and stable.

**Fix:** Always use the immutable `sub` claim (not `email`) as the primary identifier for account matching. Email can change; `sub` cannot.

---

## 8. Best Practices

### 8.1 Flow Selection Guide

```
Is a user present?
├── YES
│   ├── Is the client a public app (SPA, mobile)?
│   │   └── Authorization Code + PKCE ✓
│   ├── Is the client a server-side app?
│   │   └── Authorization Code (+ PKCE recommended) ✓
│   └── Is the device input-constrained (TV, CLI)?
│       └── Device Code Flow ✓
└── NO (machine-to-machine)
    └── Client Credentials Flow ✓

NEVER USE:
- Implicit Flow (deprecated)
- ROPC / Password Grant (deprecated)
```

### 8.2 Token Security

| Practice                                        | Why                                          |
| ----------------------------------------------- | -------------------------------------------- |
| Short access token lifetime (15–60 min)         | Limits damage from token leakage             |
| Use refresh token rotation                      | Detect stolen refresh tokens (reuse = alert) |
| Store tokens in HttpOnly cookies or server-side | Protects against XSS in SPAs                 |
| Never store tokens in localStorage              | XSS can steal them                           |
| Never log tokens                                | Prevent leakage through log aggregators      |
| Use HTTPS everywhere                            | Prevent interception                         |

### 8.3 Authorization Server Configuration

- Enforce exact `redirect_uri` matching
- Require PKCE for all public clients
- Set maximum authorization code lifetime to 60 seconds
- Implement authorization code single-use enforcement
- Enable refresh token rotation and absolute expiration
- Publish a `/.well-known/openid-configuration` discovery document
- Rotate signing keys regularly and publish via JWKS endpoint

### 8.4 Resource Server Implementation

- Validate **every** claim in the JWT: `iss`, `aud`, `exp`, `scope`
- Verify the JWT signature using the AS's public key from the JWKS endpoint (cache with TTL, don't fetch on every request)
- Check the **specific scope** required for each API endpoint
- Return `WWW-Authenticate: Bearer error="insufficient_scope"` on scope failure
- Return `WWW-Authenticate: Bearer error="invalid_token"` on token failure

### 8.5 Modern Recommendations Summary

- ✅ **Always use PKCE** — even for confidential clients (defense in depth)
- ✅ **Use short-lived access tokens** with refresh tokens
- ✅ **Use `state` parameter** — always generate and validate it
- ✅ **Use `nonce`** (in OIDC flows) to prevent ID token replay
- ✅ **Request minimal scopes** — principle of least privilege
- ✅ **Use exact redirect URI matching** — no wildcards, no prefix matching
- ✅ **Implement token binding** (DPoP or mTLS) for high-security environments
- ✅ **Use refresh token rotation** — single-use refresh tokens
- ❌ **Never use Implicit Flow**
- ❌ **Never use ROPC/Password Grant**
- ❌ **Never put tokens in query strings**
- ❌ **Never store tokens in localStorage** (use HttpOnly cookies or memory)

---

## Quick Reference: OAuth 2.0 at a Glance

```
ACTORS:
  Resource Owner     → The user who owns the data
  Client             → The app wanting access
  Authorization Server → Issues tokens (Google, Azure AD, Okta...)
  Resource Server    → The API holding the protected data

TOKENS:
  Access Token       → Short-lived, sent to APIs (Bearer header)
  Refresh Token      → Long-lived, gets new access tokens
  ID Token (OIDC)    → JWT with user identity claims

FLOWS:
  Auth Code + PKCE   → User-facing flows (preferred for all clients)
  Client Credentials → M2M, no user
  Device Code        → Input-constrained devices
  Refresh Token      → Silent token renewal

SECURITY MUSTS:
  ✓ PKCE
  ✓ state parameter
  ✓ Exact redirect_uri matching
  ✓ Short token lifetimes
  ✓ HTTPS everywhere
  ✓ Validate ALL JWT claims
```

---

## References

- [RFC 6749 — The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [RFC 7636 — PKCE for OAuth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)
- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 8628 — OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [RFC 9068 — JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)
- [OAuth 2.0 Security Best Current Practice (BCP)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [OWASP — Testing for OAuth Weaknesses](https://owasp.org/www-project-web-security-testing-guide/)
- [jwt.io — JWT Debugger](https://jwt.io)
- [OAuth 2.0 Playground (Google)](https://developers.google.com/oauthplayground)
