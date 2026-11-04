# SAML 2.0: A Technical Deep Dive

> **Prerequisite:** This document assumes thorough knowledge of OAuth 2.0 and OpenID Connect, including flows, token mechanics, PKCE, JWTs, and security considerations. SAML is approached as a parallel federation protocol with distinct mechanics, not as a replacement or extension of OAuth/OIDC.  
> **Audience:** Security engineers, IAM architects, cloud security professionals (SC-200, AZ-500, enterprise identity practitioners).

---

## Table of Contents

1. [Context and Positioning](#1-context-and-positioning)
2. [SAML Architecture and Roles](#2-saml-architecture-and-roles)
3. [SAML Assertions Deep Dive](#3-saml-assertions-deep-dive)
4. [SAML Bindings and Profiles](#4-saml-bindings-and-profiles)
5. [SAML Authentication Flow](#5-saml-authentication-flow)
6. [Protocol Internals](#6-protocol-internals)
7. [Cryptography and Trust Model](#7-cryptography-and-trust-model)
8. [Assertion Validation Process](#8-assertion-validation-process)
9. [End-to-End Example](#9-end-to-end-example)
10. [Security Deep Dive](#10-security-deep-dive)
11. [Best Practices and Modern Guidance](#11-best-practices-and-modern-guidance)

---

## 1. Context and Positioning

### 1.1 SAML in the Identity Ecosystem

SAML 2.0 (Security Assertion Markup Language, version 2.0) is an **XML-based open standard** defined by OASIS in 2005. It is a federation protocol that enables **cross-domain Single Sign-On (SSO)**: an authenticated user at one domain (the Identity Provider) can access resources at a separate domain (the Service Provider) without re-authenticating.

SAML 2.0 predates OAuth 2.0 (2012) and OIDC (2014) by several years. Despite its age, it remains the dominant protocol in:
- Enterprise B2B and B2E identity federation
- Government and regulated-industry SSO
- Legacy SaaS integrations (Salesforce, Workday, SAP)
- Microsoft Active Directory Federation Services (ADFS)
- Corporate SSO with identity providers like Okta, Ping Identity, Azure AD

### 1.2 SAML vs OAuth 2.0 vs OIDC — Precise Comparison

| Dimension | SAML 2.0 | OAuth 2.0 | OIDC |
|---|---|---|---|
| **Primary purpose** | Authentication + attribute federation | Authorization (delegated access) | Authentication (identity layer on OAuth) |
| **Token format** | XML Assertion | Opaque or JWT | JWT (ID Token) |
| **Transport** | XML over HTTP (Redirect/POST/Artifact) | HTTP with JSON payloads | HTTP with JSON payloads |
| **Trust model** | Pre-exchanged X.509 certificates + metadata | `client_id`/`client_secret` or PKCE | Same as OAuth 2.0 |
| **Signature mechanism** | XML Digital Signature (XMLDSig) | N/A (tokens validated differently) | JWS (JSON Web Signature) |
| **Encryption** | XML Encryption (EncryptedAssertion) | TLS only (for access tokens) | JWE (optional) |
| **Discovery** | Federation metadata XML | `/.well-known/openid-configuration` | Same as OAuth 2.0 |
| **Session management** | `SessionIndex` in assertion; SAML SLO | Refresh tokens | Refresh tokens + OIDC session management |
| **Browser requirement** | Yes (Web Browser SSO Profile) | Not always (Client Credentials) | Typically yes |
| **Enterprise adoption** | Dominant for enterprise SSO | Dominant for API authorization | Dominant for modern web SSO |
| **Complexity** | High (XML, certificates, metadata) | Moderate | Moderate |

The key conceptual difference: **SAML is a peer-to-peer federation protocol** between known, pre-registered entities (IdP and SP exchange metadata and certificates in advance). **OAuth/OIDC is a delegation framework** with dynamic client registration and standardized discovery.

SAML carries identity claims and authentication facts directly in its assertion. In the OAuth/OIDC world, these are split across the ID Token (identity) and access token (authorization). SAML combines both in one signed XML document.

### 1.3 When SAML Is Used

**Choose SAML when:**
- Integrating with enterprise customers who mandate it (most Fortune 500 IT departments)
- Federating with government identity systems
- Your partner's IdP is ADFS, Shibboleth, or an on-premises directory
- The application requires rich attribute assertion (role, department, clearance level) with cryptographic guarantees
- You are operating within a regulated sector (healthcare, finance, government) where SAML is contractually required

**Choose OIDC/OAuth when:**
- Building new applications with modern browsers and APIs
- Mobile or SPA clients are involved
- You need fine-grained API authorization alongside authentication
- The ecosystem is cloud-native (AWS Cognito, Azure AD B2C, Google Identity)

In practice, large enterprise identity providers (Azure AD, Okta) support **both** — the same IdP can issue SAML assertions to legacy apps and OIDC tokens to modern apps simultaneously.

---

## 2. SAML Architecture and Roles

### 2.1 Identity Provider (IdP)

The IdP is the authoritative source of user identity. It:
- Maintains a directory of users and their attributes
- Authenticates users (password, MFA, smartcard, etc.)
- Issues **SAML Assertions** asserting who the user is and what attributes they have
- Signs assertions with its private key (X.509 certificate)
- Exposes its public signing certificate and metadata for SP consumption

Examples: Microsoft ADFS, Azure AD (Entra ID), Okta, Ping Identity, Shibboleth IdP, Google Workspace.

### 2.2 Service Provider (SP)

The SP is the application or resource the user wants to access. It:
- Redirects unauthenticated users to the IdP
- Receives SAML Responses (containing assertions) at its **Assertion Consumer Service (ACS)** endpoint
- Validates the assertion signature, conditions, and subject
- Establishes a local session for the user based on the assertion's identity claims
- Does not (in the SAML model) ever see the user's password

Examples: Salesforce, Workday, custom enterprise web apps, AWS IAM (as SP for external IdP federation).

### 2.3 Principal (User)

The **Principal** is the human user whose identity is being asserted. In the Web Browser SSO Profile, the principal's browser acts as the intermediary — it carries SAML messages between the IdP and SP via HTTP redirects and form POSTs. The user's browser is **not a trusted party**: it merely transports messages and cannot forge or modify signed assertions without breaking the signature.

### 2.4 Trust Relationships and Federation Metadata

SAML trust is established **out-of-band** before any SSO occurs. The IdP and SP exchange **SAML Metadata** — an XML document describing each party's capabilities, endpoints, and public certificates.

This is fundamentally different from OAuth/OIDC, where trust can be established dynamically via a discovery document at runtime. SAML federations are static: the parties know each other in advance and have pre-registered each other's metadata.

**The trust circle:**
```
SP trusts: IdP's signing certificate (from IdP metadata)
IdP trusts: SP's ACS URL and optional SP signing certificate (from SP metadata)
Both: validated against each other's published metadata
```

If the IdP's signing certificate changes, every SP must be updated. This is one of SAML's operational pain points.

### 2.5 Role of Certificates and Trust Anchors

SAML uses **X.509 certificates** — not shared secrets — as the primary trust mechanism.

- **IdP signing certificate:** Used to sign SAML assertions and responses. SPs import this certificate and use it to verify signatures.
- **SP encryption certificate:** The SP's public key certificate. The IdP uses it to encrypt assertions (EncryptedAssertion) so only the SP can decrypt them.
- **SP signing certificate:** Some IdPs require SPs to sign AuthnRequests. The SP signs with its private key; the IdP verifies with the SP's public certificate from SP metadata.

Certificates in SAML are typically **self-signed** — the certificate itself (not a CA chain) is the trust anchor. The authenticity of the certificate is guaranteed by out-of-band metadata exchange, not by a CA hierarchy. This means certificate rotation requires coordinated metadata updates across all federation partners.

---

## 3. SAML Assertions Deep Dive

The **SAML Assertion** is the core artifact of the protocol — the XML document that asserts facts about the authenticated user. It is the SAML equivalent of a JWT, but expressed in XML with XML Digital Signature.

### 3.1 Assertion Types

SAML 2.0 defines three types of statements that can appear in an assertion:

| Statement Type | Purpose |
|---|---|
| **Authentication Statement** (`<AuthnStatement>`) | Asserts that the principal was authenticated by the IdP at a specific time using a specific method |
| **Attribute Statement** (`<AttributeStatement>`) | Asserts named attributes about the principal (e.g., email, role, department) |
| **Authorization Decision Statement** (`<AuthzDecisionStatement>`) | Asserts whether the principal is permitted to perform a specific action on a resource — rarely used in practice |

A single assertion can contain multiple statements. In Web Browser SSO, assertions almost always contain `<AuthnStatement>` and `<AttributeStatement>` together.

### 3.2 Full Sample SAML Assertion (XML)

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml:Assertion
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    xmlns:xs="http://www.w3.org/2001/XMLSchema"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    ID="_b07b804c-7571-484a-a063-e7d7a9a20573"
    Version="2.0"
    IssueInstant="2024-11-14T21:00:00Z">

  <!-- 1. ISSUER: Who issued this assertion -->
  <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>

  <!-- 2. SIGNATURE: XMLDSig over the assertion content -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#_b07b804c-7571-484a-a063-e7d7a9a20573">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue>LyLsF0Pi4wPU...==</ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue>Kx3A2Bz9mLqP...==</ds:SignatureValue>
    <ds:KeyInfo>
      <ds:X509Data>
        <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0B...</ds:X509Certificate>
      </ds:X509Data>
    </ds:KeyInfo>
  </ds:Signature>

  <!-- 3. SUBJECT: Who this assertion is about -->
  <saml:Subject>
    <saml:NameID
        Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
      shaheryar@example.com
    </saml:NameID>
    <!-- SubjectConfirmation: how the subject can be confirmed -->
    <saml:SubjectConfirmation
        Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
      <saml:SubjectConfirmationData
          NotOnOrAfter="2024-11-14T21:05:00Z"
          Recipient="https://sp.example.com/saml2/acs"
          InResponseTo="_adf43daj3209faj3daj32f09aj3f09aj3f"/>
    </saml:SubjectConfirmation>
  </saml:Subject>

  <!-- 4. CONDITIONS: Time validity and audience restriction -->
  <saml:Conditions
      NotBefore="2024-11-14T20:59:50Z"
      NotOnOrAfter="2024-11-14T21:05:00Z">
    <saml:AudienceRestriction>
      <saml:Audience>https://sp.example.com/saml2/metadata</saml:Audience>
    </saml:AudienceRestriction>
  </saml:Conditions>

  <!-- 5. AUTHN STATEMENT: Authentication event details -->
  <saml:AuthnStatement
      AuthnInstant="2024-11-14T20:59:45Z"
      SessionIndex="_session-7a3f2b9c-1234-5678-abcd-ef0123456789"
      SessionNotOnOrAfter="2024-11-14T29:00:00Z">
    <saml:AuthnContext>
      <saml:AuthnContextClassRef>
        urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
      </saml:AuthnContextClassRef>
    </saml:AuthnContext>
  </saml:AuthnStatement>

  <!-- 6. ATTRIBUTE STATEMENT: User attributes -->
  <saml:AttributeStatement>
    <saml:Attribute
        Name="urn:oid:1.3.6.1.4.1.5923.1.1.1.7"
        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        FriendlyName="eduPersonEntitlement">
      <saml:AttributeValue xsi:type="xs:string">security-analyst</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute
        Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        FriendlyName="email">
      <saml:AttributeValue xsi:type="xs:string">shaheryar@example.com</saml:AttributeValue>
    </saml:Attribute>

    <saml:Attribute
        Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
        NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        FriendlyName="role">
      <saml:AttributeValue xsi:type="xs:string">Analyst</saml:AttributeValue>
      <saml:AttributeValue xsi:type="xs:string">Viewer</saml:AttributeValue>
    </saml:Attribute>
  </saml:AttributeStatement>

</saml:Assertion>
```

### 3.3 Annotated Breakdown of Each Element

#### `<saml:Assertion>` Root Element

```xml
<saml:Assertion
    ID="_b07b804c-7571-484a-a063-e7d7a9a20573"
    Version="2.0"
    IssueInstant="2024-11-14T21:00:00Z">
```

| Attribute | Significance |
|---|---|
| `ID` | Globally unique identifier for this assertion. The `_` prefix is required by XML ID rules. This ID is referenced by the `<ds:Reference URI="#">` in the signature — the signature is over *this specific assertion element*. It is also used for replay detection. |
| `Version` | Always `2.0` for SAML 2.0. |
| `IssueInstant` | UTC timestamp of issuance. Used by SPs to detect stale assertions (should be within a short window of receipt). |

#### `<saml:Issuer>`

Identifies the IdP by its **entity ID** — a URI (typically a URL) that uniquely identifies the issuer. The SP must verify this matches the expected IdP entity ID from its metadata configuration. Never trust assertions from unexpected issuers.

#### `<ds:Signature>` (XMLDSig)

The XML Digital Signature is embedded inside the assertion (enveloped signature). Critical elements:

- `CanonicalizationMethod`: Before signing, XML is **canonicalized** (normalized to a canonical byte sequence) to ensure that whitespace, namespace prefix variations, and attribute ordering don't affect the digest. The algorithm specified here defines the canonicalization method used.
- `SignatureMethod`: The signing algorithm. **Always require `rsa-sha256` or `ecdsa-sha256`**. Reject `rsa-sha1` (SHA-1 is broken for this purpose).
- `Reference URI`: Points to the assertion element by its `ID`. This anchors the signature to exactly this XML element. XSW attacks (Section 10) exploit mismatches between what is signed and what is processed.
- `Transforms`: Applied to the referenced element before digesting. `enveloped-signature` removes the signature element itself before digesting (prevents circular reference). `exc-c14n` canonicalizes the result.
- `DigestValue`: SHA-256 hash of the transformed, canonicalized assertion content.
- `SignatureValue`: RSA signature over the `SignedInfo` block.
- `X509Certificate`: The IdP's public certificate embedded in the signature. **Note:** The SP must not blindly trust the certificate embedded here — it must be matched against the trusted certificate from the IdP's pre-registered metadata.

#### `<saml:Subject>`

Identifies who the assertion is about.

**`<saml:NameID>`** is the principal identifier. The `Format` attribute determines its semantics:

| NameID Format | URI | Usage |
|---|---|---|
| `emailAddress` | `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress` | User's email. Human-readable but mutable (email can change). |
| `persistent` | `urn:oasis:names:tc:SAML:2.0:nameid-format:persistent` | Opaque, stable, per SP-IdP pair identifier. Like OIDC `sub`. Preferred for stable identity. |
| `transient` | `urn:oasis:names:tc:SAML:2.0:nameid-format:transient` | Random, session-scoped. Changes every login. For privacy-preserving scenarios. |
| `unspecified` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified` | No specific format guaranteed. |
| `X509SubjectName` | `urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName` | X.509 certificate subject name. |
| `WindowsDomainQualifiedName` | `urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName` | Windows domain login format. |

**`<saml:SubjectConfirmation>`** with `Method="bearer"` means: whoever presents this assertion to the SP is accepted as the subject, as long as they do so within the time and to the recipient specified in `SubjectConfirmationData`.

- `NotOnOrAfter`: Assertion must be consumed before this time.
- `Recipient`: The ACS URL where the assertion is to be delivered. SP must verify this matches its own ACS URL.
- `InResponseTo`: The `ID` of the `AuthnRequest` that triggered this assertion. Binds the assertion to a specific authentication request. Prevents unsolicited assertion injection (critical for IdP-initiated flow security).

#### `<saml:Conditions>`

Time validity window for the assertion.

- `NotBefore`: Assertion is not valid before this time. SPs should allow small clock skew (typically ±5 minutes).
- `NotOnOrAfter`: Assertion is not valid at or after this time. Short windows (2–5 minutes) are recommended.

**`<saml:AudienceRestriction>`** restricts which SPs may consume this assertion. `<saml:Audience>` is the SP's entity ID. The SP must verify its own entity ID is in the AudienceRestriction. Missing this check allows assertions meant for one SP to be replayed against another.

#### `<saml:AuthnStatement>`

Asserts the authentication event.

- `AuthnInstant`: When the user actually authenticated (not when the assertion was issued).
- `SessionIndex`: Unique identifier for the IdP's authentication session. Used in **Single Logout (SLO)**: the SP sends this back to the IdP in a `LogoutRequest` to terminate the correct session.
- `SessionNotOnOrAfter`: When the IdP's session expires. The SP should not extend its local session beyond this.

**`<saml:AuthnContextClassRef>`** indicates the authentication method:

| Value | Meaning |
|---|---|
| `PasswordProtectedTransport` | Password over HTTPS |
| `Password` | Password (transport not specified) |
| `TimeSyncToken` | OTP/TOTP second factor |
| `Smartcard` | Hardware smartcard |
| `SmartcardPKI` | Smartcard with PKI |
| `MobileTwoFactorContract` | Mobile-based MFA |
| `X509` | X.509 certificate authentication |

SPs can require a minimum `AuthnContextClassRef` for access to sensitive resources.

#### `<saml:AttributeStatement>`

Contains named attributes about the user. Each `<saml:Attribute>` has:
- `Name`: Attribute identifier (URI or OID-based).
- `NameFormat`: How the name should be interpreted (`uri`, `basic`, or `unspecified`).
- `FriendlyName`: Human-readable name (optional, not authoritative).
- Multiple `<saml:AttributeValue>` elements for multi-valued attributes (e.g., multiple roles).

Attribute names are not standardized across all IdPs — a significant operational challenge. ADFS, Okta, and Shibboleth use different naming conventions for the same concepts. The attribute mapping must be configured per federation pair.

---

## 4. SAML Bindings and Profiles

SAML separates the **what** (the protocol messages — assertions, requests) from the **how** (how those messages travel over the network — bindings).

### 4.1 Bindings

#### HTTP Redirect Binding

Used for **sending SAML messages as URL parameters**. Only suitable for small messages (AuthnRequests). Not suitable for full SAML Responses (assertions are too large for URLs).

Encoding pipeline:
```
XML Message
  → DEFLATE compression (RFC 1951)
  → Base64 encoding
  → URL encoding
  → Appended as query parameter: ?SAMLRequest=<encoded>
```

Example URL:
```
https://idp.example.com/saml2/sso?
  SAMLRequest=fZJbT4MwFIX%2FCtl7hY0rlAzJZFnURV%2FM...
  &RelayState=https%3A%2F%2Fsp.example.com%2Fdashboard
  &SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
  &Signature=Kx3A2Bz9mLqP...
```

Signatures in Redirect Binding are **not XML signatures** — they are computed over the query string parameters (`SAMLRequest=...&RelayState=...&SigAlg=...`) using the SP's private key, and appended as a separate `Signature` query parameter.

#### HTTP POST Binding

Used for **sending SAML messages as HTML form fields**. This is the standard binding for SAML Responses (assertions).

The message travels as the value of an HTML `<input type="hidden">` field. The browser automatically submits the form to the SP's ACS URL.

Encoding pipeline:
```
XML Message
  → Base64 encoding (no DEFLATE — POST can handle large payloads)
  → Embedded in HTML form as hidden field value
  → Browser POSTs the form to the ACS URL
```

HTML form structure:
```html
<html>
  <body onload="document.forms[0].submit()">
    <form method="POST" action="https://sp.example.com/saml2/acs">
      <input type="hidden" name="SAMLResponse"
             value="PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoyLjA6cHJvdG9jb2wiIC4uLj4="/>
      <input type="hidden" name="RelayState"
             value="https://sp.example.com/dashboard"/>
    </form>
  </body>
</html>
```

The IdP returns this HTML page; the `onload` JavaScript immediately submits the form. The user sees no visible interaction — the browser appears to redirect, but it's actually a POST.

The XML signature in POST binding is an **enveloped XMLDSig** embedded within the XML document itself (as shown in the assertion example above).

#### HTTP Artifact Binding

A three-party binding where the SAML message is not sent directly to the SP but is instead stored at the IdP and referenced by a short **artifact** (an opaque handle).

```
1. IdP generates artifact: <short opaque reference>
2. IdP redirects browser to SP ACS: ?SAMLart=<artifact>
3. SP sends ArtifactResolve request directly to IdP (back-channel SOAP call)
4. IdP returns the full SAML Response in an ArtifactResponse
```

Advantages: The SAML Response never travels through the browser — eliminates browser-history leakage of assertions. Requires direct network connectivity between SP and IdP (back-channel SOAP).

Rarely used in modern deployments due to complexity and SOAP dependency. Most deployments use POST binding.

### 4.2 Profiles

#### Web Browser SSO Profile

The primary SAML 2.0 usage profile. Defines how the Redirect and POST bindings are combined to implement browser-based SSO. This is what virtually all enterprise SAML deployments use.

The profile specifies:
- The SP must use HTTP Redirect or HTTP POST binding for the `AuthnRequest`
- The IdP must use HTTP POST binding for the `SAMLResponse` (to the SP's ACS URL)
- The assertion must use Bearer `SubjectConfirmation`

#### SP-Initiated vs IdP-Initiated

**SP-Initiated SSO:** The user first visits the SP, which generates an `AuthnRequest` and redirects to the IdP. The IdP's assertion includes `InResponseTo` pointing to the `AuthnRequest.ID`. This is the more secure and recommended flow.

**IdP-Initiated SSO:** The user begins at the IdP (e.g., an enterprise portal/launchpad). The IdP generates an assertion without a preceding `AuthnRequest`. No `InResponseTo` is present. The assertion is POSTed directly to the SP's ACS URL. This is operationally convenient but carries significant security implications (Section 10).

---

## 5. SAML Authentication Flow

### 5.1 SP-Initiated SSO Flow — Step by Step

```
User Browser              Service Provider (SP)           Identity Provider (IdP)
     |                           |                                  |
     |--- GET /resource -------->|                                  |
     |                           | (user not authenticated)         |
     |                           | generate AuthnRequest            |
     |<-- 302 to IdP SSO --------|                                  |
     |    ?SAMLRequest=...       |                                  |
     |    &RelayState=...        |                                  |
     |                           |                                  |
     |--- GET IdP SSO ---------->|                                  |
     |    ?SAMLRequest=...  -----|---------------GET--------------->|
     |                           |                                  |
     |<-- IdP login page --------|<---------------------------------|
     |--- credentials ---------->|                                  |
     |   (user authenticates) ---|---------(verification)---------->|
     |                           |                                  |
     |                           |    IdP generates SAMLResponse   |
     |                           |    with signed Assertion        |
     |<-- HTML form (autosubmit)|<--POST HTML form----------------|
     |    SAMLResponse=...       |                                  |
     |--- POST /acs ------------>|                                  |
     |    SAMLResponse=...       |                                  |
     |                           | validate assertion               |
     |                           | establish local session          |
     |<-- 302 to /resource ------|                                  |
     |--- GET /resource -------->|                                  |
     |<-- protected resource ----|                                  |
```

#### Step 1: User Accesses SP Resource

```http
GET /dashboard HTTP/1.1
Host: sp.example.com
```

SP detects no local session → initiates SAML SSO.

#### Step 2: SP Generates AuthnRequest

SP creates a signed `AuthnRequest` XML, DEFLATE-compresses, Base64-encodes, and URL-encodes it. Stores `RelayState` (the original URL the user wanted) in its session.

```http
HTTP/1.1 302 Found
Location: https://idp.example.com/saml2/sso?
  SAMLRequest=fZJbT4MwFIX%2FCtl7hY...
  &RelayState=aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ%3D
  &SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
  &Signature=Kx3A2Bz9mLqP...
```

#### Step 3: IdP Processes AuthnRequest

The browser follows the redirect to the IdP's SSO endpoint. The IdP:
1. Decodes and parses the `SAMLRequest`
2. Validates the SP's signature (using SP's certificate from metadata)
3. Validates `Destination` matches this IdP's SSO endpoint
4. Extracts and stores the `AuthnRequest.ID` for the `InResponseTo` field

#### Step 4: User Authentication

IdP presents its login page. User authenticates (password, MFA, smartcard, etc.). IdP records `AuthnInstant`, `AuthnContextClassRef`, and generates a `SessionIndex`.

#### Step 5: IdP Generates SAML Response

IdP constructs the `<samlp:Response>` containing:
- A signed `<saml:Assertion>` (or encrypted `<saml:EncryptedAssertion>`)
- `InResponseTo` set to the `AuthnRequest.ID`
- `Destination` set to the SP's ACS URL

IdP signs the assertion (and optionally the response envelope) using its private key.

IdP returns the HTML auto-submit form:

```html
<html>
<body onload="document.forms[0].submit()">
  <form method="POST" action="https://sp.example.com/saml2/acs">
    <input type="hidden" name="SAMLResponse" value="PHNhbWxwOlJlc3BvbnNlIC4uLj4="/>
    <input type="hidden" name="RelayState"
           value="aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ="/>
  </form>
</body>
</html>
```

#### Step 6: Browser POSTs to SP ACS

The browser automatically submits the form to the SP's ACS URL:

```http
POST /saml2/acs HTTP/1.1
Host: sp.example.com
Content-Type: application/x-www-form-urlencoded

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIC4uLj4%3D&RelayState=aHR0cH...
```

#### Step 7: SP Validates Assertion

SP performs the full validation (Section 8). On success:
- Establishes a local authenticated session
- Extracts user identity from `NameID` and attributes from `AttributeStatement`
- Redirects user to the original resource (from `RelayState`)

```http
HTTP/1.1 302 Found
Location: https://sp.example.com/dashboard
Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax
```

---

### 5.2 IdP-Initiated Flow

The user navigates to the IdP portal (e.g., `https://mycompany.okta.com`), selects an app tile, and the IdP directly POSTs a SAML assertion to the SP's ACS URL without a preceding `AuthnRequest`.

**Key differences:**
- No `AuthnRequest` is generated by the SP
- No `InResponseTo` in the assertion — there is no request ID to reference
- The SP receives an unsolicited assertion at its ACS endpoint
- `RelayState` may be set by the IdP to indicate which resource to redirect to after login

**Security implications:**
- Without `InResponseTo`, the SP cannot verify the assertion was issued in response to *its* request
- An attacker who captures a valid IdP-initiated assertion can replay it against the SP (no `InResponseTo` to detect the replay)
- SPs should have replay detection based on assertion `ID` even for IdP-initiated flows
- Some SPs reject IdP-initiated assertions entirely for high-security applications

---

## 6. Protocol Internals

### 6.1 AuthnRequest Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_adf43daj3209faj3daj32f09aj3f09aj3f"
    Version="2.0"
    IssueInstant="2024-11-14T20:59:50Z"
    Destination="https://idp.example.com/saml2/sso"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
    AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"
    ForceAuthn="false"
    IsPassive="false">

  <!-- SP entity ID: who is requesting authentication -->
  <saml:Issuer>https://sp.example.com/saml2/metadata</saml:Issuer>

  <!-- Optional: request a specific NameID format -->
  <samlp:NameIDPolicy
      Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
      AllowCreate="true"/>

  <!-- Optional: request a minimum authentication level -->
  <samlp:RequestedAuthnContext Comparison="minimum">
    <saml:AuthnContextClassRef>
      urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
    </saml:AuthnContextClassRef>
  </samlp:RequestedAuthnContext>

</samlp:AuthnRequest>
```

| Element/Attribute | Purpose |
|---|---|
| `ID` | Unique request identifier. Stored by SP; verified in `InResponseTo` of the response. |
| `Destination` | IdP SSO endpoint URL. IdP must verify this matches its own endpoint (prevents request forwarding). |
| `AssertionConsumerServiceURL` | Where the IdP should send the response. IdP must validate this matches a registered ACS URL in SP metadata. |
| `ProtocolBinding` | Which binding to use for the response (typically HTTP-POST). |
| `ForceAuthn` | If `true`, IdP must re-authenticate the user even if an active session exists. |
| `IsPassive` | If `true`, IdP must not display any UI — return an error if authentication cannot proceed silently. |
| `NameIDPolicy` | Requested NameID format and whether the IdP may create a new persistent identifier. |
| `RequestedAuthnContext` | Minimum required authentication strength. `Comparison` can be `exact`, `minimum`, `maximum`, or `better`. |

### 6.2 SAML Response Structure

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response-id-8f7e6d5c-4b3a-2c1d-0e9f-8a7b6c5d4e3f"
    Version="2.0"
    IssueInstant="2024-11-14T21:00:00Z"
    Destination="https://sp.example.com/saml2/acs"
    InResponseTo="_adf43daj3209faj3daj32f09aj3f09aj3f">

  <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>

  <!-- Optional: response-level signature (in addition to assertion-level) -->
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
    <!-- ... signature over the Response element ... -->
  </ds:Signature>

  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <!-- The signed (or encrypted) assertion -->
  <saml:Assertion ...>
    <!-- Full assertion as shown in Section 3 -->
  </saml:Assertion>

</samlp:Response>
```

The `<samlp:Status>` element indicates whether authentication succeeded. Status codes:

| Status Code | Meaning |
|---|---|
| `Success` | Authentication successful |
| `Requester` | Error caused by the request (bad AuthnRequest) |
| `Responder` | Error at the IdP side |
| `VersionMismatch` | Unsupported SAML version |
| `AuthnFailed` | Authentication failure |
| `NoAuthnContext` | Requested AuthnContext could not be satisfied |
| `RequestDenied` | IdP refused the request |

### 6.3 RelayState

`RelayState` is an opaque value passed alongside SAML messages throughout the flow. It allows the SP to maintain state across the round-trip to the IdP and back. Typically used to store the URL the user originally requested, so they can be redirected there after successful authentication.

`RelayState` is **not** signed or encrypted by default. It travels through the user's browser. Security implications:
- Must not contain sensitive information
- Open redirect risk if the SP uses RelayState as a redirect target without validation (Section 10)
- Maximum recommended length: 80 bytes (per SAML spec recommendation)

### 6.4 NameID Formats (Extended)

The `persistent` NameID format deserves special attention. It is the SAML equivalent of OIDC's `sub` claim:

- **Opaque:** Not the user's email or username
- **Stable:** Same value for the same user across all sessions
- **Pair-wise (optionally):** The IdP can issue different persistent NameIDs to different SPs for the same user, preventing correlation across SPs (privacy-preserving federation)
- **Managed by IdP:** The user cannot change it; it is controlled by the IdP

For enterprise SSO, `persistent` is the recommended format. Using `emailAddress` as a NameID is problematic because email addresses can change, and they leak user information.

### 6.5 Session Management with SessionIndex

The `SessionIndex` attribute in `<saml:AuthnStatement>` uniquely identifies the IdP's authentication session. It is the key to **SAML Single Logout (SLO)**.

**SLO flow:**
```
1. User logs out of SP
2. SP sends LogoutRequest to IdP with SessionIndex
3. IdP terminates its session
4. IdP sends LogoutRequest to all other SPs that share this SessionIndex
5. Each SP terminates its local session
6. IdP sends LogoutResponse back to the initiating SP
```

SLO is notoriously difficult to implement reliably (SPs may be unreachable, browser may close before SLO completes). Many deployments implement only local SP logout and accept that the IdP session may remain active.

---

## 7. Cryptography and Trust Model

### 7.1 XML Digital Signature (XMLDSig)

SAML uses the W3C XML Digital Signature standard ([XMLDSig](https://www.w3.org/TR/xmldsig-core/)). This is significantly more complex than JWT signing (JWS) due to XML's flexible structure.

**Three signature types by placement:**

| Type | Signature location | Reference |
|---|---|---|
| **Enveloped** | Signature is inside the signed element | `URI="#assertion-id"` + `enveloped-signature` transform |
| **Enveloping** | Signed content is inside the `<Object>` element of the signature | Less common in SAML |
| **Detached** | Signature is separate from the signed document | External reference |

SAML primarily uses **enveloped signatures**.

**The signing and verification process:**

```
SIGNING:
1. Identify the element to sign (Assertion or Response), noted by its ID
2. Apply transforms: remove signature element (enveloped-signature), then canonicalize
3. Compute digest: SHA-256(canonicalized_content) → DigestValue
4. Construct SignedInfo: CanonicalizationMethod + SignatureMethod + Reference(with DigestValue)
5. Canonicalize SignedInfo
6. Sign: RSA_SHA256(canonicalized_SignedInfo, private_key) → SignatureValue
7. Embed signature in the XML document

VERIFICATION:
1. Extract the signature element and its Reference URI
2. Locate the element referenced by URI (should be the Assertion or Response)
3. Apply the same transforms (CRITICAL: this must match the signed transforms)
4. Recompute digest and compare to DigestValue → verifies content integrity
5. Verify SignatureValue against canonicalized SignedInfo using IdP's public key
6. The public key must come from trusted IdP metadata, NOT from the embedded X509Certificate alone
```

#### Canonicalization — Why It Matters

XML can be semantically equivalent but syntactically different (different namespace declarations, whitespace, attribute ordering). Without canonicalization, the same logical XML would produce different byte sequences and thus different digests. SAML requires **Exclusive XML Canonicalization (exc-c14n)** — `http://www.w3.org/2001/10/xml-exc-c14n#`. This produces a canonical byte sequence regardless of these variations.

### 7.2 What Gets Signed

There are three configurations, with different security properties:

| What is signed | Security level | Notes |
|---|---|---|
| **Assertion only** | Moderate | Only the Assertion is integrity-protected. Response metadata (status, destination) is unprotected. Most common configuration. |
| **Response only** | Weaker | The Assertion inside the Response may not be individually authenticated. Allows wrapping attacks targeting the Assertion. |
| **Both Assertion and Response** | Strongest | Defense-in-depth. Recommended for high-assurance deployments. |

SPs should be configured to require assertion-level signatures. Accepting response-only signatures is risky.

### 7.3 XML Encryption (EncryptedAssertion)

The assertion can be encrypted so only the intended SP can read it:

```xml
<samlp:Response ...>
  <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <!-- Assertion is encrypted — opaque to the browser and any intermediaries -->
  <saml:EncryptedAssertion>
    <xenc:EncryptedData
        xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
        Type="http://www.w3.org/2001/04/xmlenc#Element">
      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <xenc:EncryptedKey>
          <!-- AES key encrypted with SP's RSA public key -->
          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/>
          <xenc:CipherData>
            <xenc:CipherValue>cGFzc3dvcmQ=...</xenc:CipherValue>
          </xenc:CipherData>
        </xenc:EncryptedKey>
      </ds:KeyInfo>
      <xenc:CipherData>
        <xenc:CipherValue>
          <!-- AES-256-CBC encrypted assertion content -->
          UmVhbGx5IGVuY3J5cHRlZCBkYXRhLi4u
        </xenc:CipherValue>
      </xenc:CipherData>
    </xenc:EncryptedData>
  </saml:EncryptedAssertion>
</samlp:Response>
```

The encryption uses a hybrid scheme:
1. A random symmetric key (AES-256) is generated per assertion
2. The assertion XML is encrypted with AES-256-CBC (or AES-256-GCM in modern implementations)
3. The AES key is encrypted with the SP's RSA public key (RSA-OAEP)
4. Only the SP can decrypt the AES key (with its RSA private key), then decrypt the assertion

**Sign-then-encrypt order:** The assertion must be **signed before encryption** — `sign(assertion)` → `encrypt(signed_assertion)`. Encrypting before signing means the signature is over the ciphertext, not the assertion content, which breaks the integrity guarantee.

### 7.4 Federation Metadata

The **SAML Metadata** document is the out-of-band trust anchor. Both IdP and SP publish metadata that the other party imports to configure the federation.

#### Sample IdP Metadata

```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://idp.example.com/saml2/idp/metadata"
    validUntil="2025-11-14T00:00:00Z">

  <md:IDPSSODescriptor
      WantAuthnRequestsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- Signing certificate: SPs import this to verify assertion signatures -->
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0B...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- Encryption certificate: IdP uses this to encrypt assertions for SPs -->
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADANBgkqhkiG9w0B...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- Single Logout endpoint -->
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/saml2/slo"/>

    <!-- NameID formats supported -->
    <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>

    <!-- SSO endpoint -->
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://idp.example.com/saml2/sso"/>
    <md:SingleSignOnService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://idp.example.com/saml2/sso"/>

  </md:IDPSSODescriptor>

</md:EntityDescriptor>
```

#### Sample SP Metadata

```xml
<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor
    xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"
    entityID="https://sp.example.com/saml2/metadata">

  <md:SPSSODescriptor
      AuthnRequestsSigned="true"
      WantAssertionsSigned="true"
      protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">

    <!-- SP signing certificate (for signed AuthnRequests) -->
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADAN...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- SP encryption certificate (for EncryptedAssertion) -->
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
        <ds:X509Data>
          <ds:X509Certificate>MIICajCCAdOgAwIBAgIBADAN...</ds:X509Certificate>
        </ds:X509Data>
      </ds:KeyInfo>
    </md:KeyDescriptor>

    <!-- Where the IdP should POST assertions -->
    <md:AssertionConsumerService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        Location="https://sp.example.com/saml2/acs"
        index="1"
        isDefault="true"/>

    <!-- Single Logout endpoint -->
    <md:SingleLogoutService
        Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
        Location="https://sp.example.com/saml2/slo"/>

  </md:SPSSODescriptor>

</md:EntityDescriptor>
```

| Metadata Field | Significance |
|---|---|
| `entityID` | The entity's unique identifier in the federation. Every SAML message includes `<Issuer>` which must match this. |
| `WantAuthnRequestsSigned` (IdP) | IdP requires SP to sign AuthnRequests. |
| `WantAssertionsSigned` (SP) | SP requires assertions to be signed. Should always be `true`. |
| `AuthnRequestsSigned` (SP) | SP declares it will sign AuthnRequests. |
| `validUntil` | Metadata expiry. SPs should reject expired metadata. |
| `KeyDescriptor use="signing"` | Certificate for signature operations. |
| `KeyDescriptor use="encryption"` | Certificate for encryption operations. |

---

## 8. Assertion Validation Process

The SP must perform all of the following checks upon receiving a SAML Response. Skipping any is a security vulnerability.

```
Step 1: Decode the SAMLResponse
  - Base64-decode the SAMLResponse form parameter
  - Parse the resulting XML

Step 2: Validate the Response structure
  - Response must be valid XML
  - Namespace declarations must be correct
  - samlp:Response must be the root element

Step 3: Check StatusCode
  - samlp:StatusCode Value must be "Success"
  - If not, reject and log appropriately

Step 4: Validate Destination
  - Response/Destination must exactly match the SP's ACS URL
  - Reject if absent or mismatched (prevents forwarded responses)

Step 5: Validate InResponseTo (SP-Initiated flows)
  - Response/InResponseTo must match the ID of an outstanding AuthnRequest
  - The SP must maintain a list of pending AuthnRequest IDs
  - Reject if InResponseTo references an unknown, expired, or already-consumed request

Step 6: Decrypt EncryptedAssertion (if encrypted)
  - Decrypt the AES key using SP's RSA private key
  - Decrypt the assertion content using the AES key
  - Continue validation on the decrypted assertion

Step 7: Verify the Assertion signature
  - Locate the ds:Signature element within the Assertion
  - Extract the Reference URI and confirm it matches the Assertion ID
  - Apply the specified transforms to the Assertion element
  - Recompute the digest and compare to ds:DigestValue
  - Verify the ds:SignatureValue using the IdP's public key from TRUSTED METADATA
  - DO NOT trust the X509Certificate embedded in ds:KeyInfo alone
  - The certificate from KeyInfo must match the certificate in IdP metadata

Step 8: Validate Issuer
  - saml:Issuer (in Assertion) must match the expected IdP entityID
  - Reject if unknown or unexpected issuer

Step 9: Validate Conditions
  - Check NotBefore: current_time >= NotBefore (allow ±5 minute clock skew)
  - Check NotOnOrAfter: current_time < NotOnOrAfter
  - Reject if outside the valid window

Step 10: Validate AudienceRestriction
  - saml:Audience must contain the SP's entityID
  - Reject if SP's entityID is not present (prevents cross-SP assertion reuse)

Step 11: Validate SubjectConfirmation
  - Method must be "bearer" for Web Browser SSO
  - SubjectConfirmationData/NotOnOrAfter: current_time < NotOnOrAfter
  - SubjectConfirmationData/Recipient: must match SP's ACS URL
  - SubjectConfirmationData/InResponseTo: must match outstanding AuthnRequest ID

Step 12: Replay Detection
  - Check Assertion ID against a short-term cache of recently seen assertion IDs
  - If already seen: REJECT (replay attack)
  - Add current assertion ID to the cache (retain for at least NotOnOrAfter duration)

Step 13: Validate AuthnStatement
  - AuthnInstant must be in the past
  - If SP requested RequestedAuthnContext, verify AuthnContextClassRef meets the requirement
  - If max session age is enforced, verify SessionNotOnOrAfter

Step 14: Extract Identity
  - Extract NameID (value and Format)
  - Extract attributes from AttributeStatement
  - Map attributes to application roles/claims
  - Establish local session
```

### Comparison with JWT Validation (OIDC)

| Aspect | SAML Assertion | JWT (ID Token) |
|---|---|---|
| **Signature format** | XMLDSig (complex, canonicalization required) | JWS (simple: base64url header.payload, HMAC or RSA/EC) |
| **Key retrieval** | Certificate from pre-registered IdP metadata | Public key from JWKS endpoint (dynamic) |
| **Replay protection** | Assertion ID cache (must implement manually) | `nonce` claim + client-side state |
| **Audience** | `<AudienceRestriction>` element | `aud` claim |
| **Expiry** | `NotOnOrAfter` in Conditions | `exp` claim |
| **Issuer** | `<Issuer>` element | `iss` claim |
| **Subject** | `<NameID>` with Format attribute | `sub` claim (always opaque string) |
| **Authentication method** | `AuthnContextClassRef` | `acr`, `amr` claims |
| **Session binding** | `SessionIndex` | `sid` claim (OIDC session management) |
| **Encryption** | `EncryptedAssertion` (XML Encryption) | JWE (JSON Web Encryption) |
| **Library support** | Complex, limited high-quality libraries | Rich ecosystem (jose, nimbus, etc.) |

The critical practical difference: JWT validation is well-understood, with standardized libraries and simple parsing. XMLDSig validation is notoriously complex, with many historical vulnerabilities stemming from incorrect implementation (particularly XSW attacks exploiting transform misapplication).

---

## 9. End-to-End Example

A complete SP-initiated SAML SSO exchange. User accesses `https://sp.example.com/dashboard`.

---

### Step 1: SP Detects Unauthenticated User

```http
GET /dashboard HTTP/1.1
Host: sp.example.com
```

SP has no session cookie. Generates AuthnRequest.

---

### Step 2: SP Generates and Encodes AuthnRequest

**Raw AuthnRequest XML:**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_adf43daj3209faj3daj32f09aj3f09aj3f"
    Version="2.0"
    IssueInstant="2024-11-14T20:59:50Z"
    Destination="https://idp.example.com/saml2/sso"
    AssertionConsumerServiceURL="https://sp.example.com/saml2/acs"
    ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
  <saml:Issuer>https://sp.example.com/saml2/metadata</saml:Issuer>
  <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" AllowCreate="true"/>
</samlp:AuthnRequest>
```

**Encoding:**
```
1. DEFLATE compress the XML
2. Base64 encode: "fZJbT4MwFIX/Ctl7hY0rlAzJZFnURV/..."
3. URL encode: "fZJbT4MwFIX%2FCtl7hY0rlAzJZFnURV%2F..."
```

SP stores in session:
- `authnRequestId = "_adf43daj3209faj3daj32f09aj3f09aj3f"`
- `relayState = "aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ="` (Base64 of original URL)

---

### Step 3: SP Redirects Browser to IdP

```http
HTTP/1.1 302 Found
Location: https://idp.example.com/saml2/sso?
  SAMLRequest=fZJbT4MwFIX%2FCtl7hY0rlAzJZFnURV%2F...
  &RelayState=aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ%3D
  &SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256
  &Signature=Kx3A2Bz9mLqP1r4s7t2u5v8w0x3y6z9a2b...
```

---

### Step 4: Browser Follows Redirect to IdP

```http
GET /saml2/sso?SAMLRequest=fZJbT4MwFIX...&RelayState=aHR0...&SigAlg=...&Signature=... HTTP/1.1
Host: idp.example.com
```

IdP decodes and validates the AuthnRequest. Presents login form.

---

### Step 5: User Authenticates

```http
POST /saml2/sso/authenticate HTTP/1.1
Host: idp.example.com
Content-Type: application/x-www-form-urlencoded

username=shaheryar%40example.com&password=...&mfa_token=123456
```

IdP validates credentials and MFA. Authentication successful.

---

### Step 6: IdP Generates SAML Response

IdP constructs and signs the assertion, wraps it in a Response, and Base64-encodes it.

**SAML Response XML (decoded from Base64):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:Response
    xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
    xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
    ID="_response-8f7e6d5c-4b3a-2c1d-0e9f"
    Version="2.0"
    IssueInstant="2024-11-14T21:00:00Z"
    Destination="https://sp.example.com/saml2/acs"
    InResponseTo="_adf43daj3209faj3daj32f09aj3f09aj3f">

  <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>

  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>

  <saml:Assertion
      ID="_b07b804c-7571-484a-a063-e7d7a9a20573"
      Version="2.0"
      IssueInstant="2024-11-14T21:00:00Z">

    <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>

    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <!-- ... signature over assertion _b07b804c-... ... -->
    </ds:Signature>

    <saml:Subject>
      <saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
        _uid-e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b
      </saml:NameID>
      <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
        <saml:SubjectConfirmationData
            NotOnOrAfter="2024-11-14T21:05:00Z"
            Recipient="https://sp.example.com/saml2/acs"
            InResponseTo="_adf43daj3209faj3daj32f09aj3f09aj3f"/>
      </saml:SubjectConfirmation>
    </saml:Subject>

    <saml:Conditions
        NotBefore="2024-11-14T20:59:50Z"
        NotOnOrAfter="2024-11-14T21:05:00Z">
      <saml:AudienceRestriction>
        <saml:Audience>https://sp.example.com/saml2/metadata</saml:Audience>
      </saml:AudienceRestriction>
    </saml:Conditions>

    <saml:AuthnStatement
        AuthnInstant="2024-11-14T20:59:55Z"
        SessionIndex="_session-7a3f2b9c-1234-5678-abcd">
      <saml:AuthnContext>
        <saml:AuthnContextClassRef>
          urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport
        </saml:AuthnContextClassRef>
      </saml:AuthnContext>
    </saml:AuthnStatement>

    <saml:AttributeStatement>
      <saml:Attribute Name="email" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>shaheryar@example.com</saml:AttributeValue>
      </saml:Attribute>
      <saml:Attribute Name="role" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
        <saml:AttributeValue>Analyst</saml:AttributeValue>
      </saml:Attribute>
    </saml:AttributeStatement>

  </saml:Assertion>
</samlp:Response>
```

**Base64-encoded (SAMLResponse value):**
```
PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6dGM6U0FNTDoy
LjA6cHJvdG9jb2wiIHhtbG5zOnNhbWw9InVybjpvYXNpczpuYW1lczp0YzpTQU1MOjIuMDph
c3NlcnRpb24iIElEPSJfcmVzcG9uc2UtOGY3...
```

---

### Step 7: IdP Returns HTML Auto-Submit Form

```html
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8

<!DOCTYPE html>
<html>
<head><title>Redirecting...</title></head>
<body onload="document.forms[0].submit()">
  <noscript>
    <p>JavaScript is required. <button form="saml-form">Continue</button></p>
  </noscript>
  <form id="saml-form" method="POST" action="https://sp.example.com/saml2/acs">
    <input type="hidden" name="SAMLResponse"
           value="PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6..."/>
    <input type="hidden" name="RelayState"
           value="aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ="/>
  </form>
</body>
</html>
```

---

### Step 8: Browser POSTs to SP ACS

```http
POST /saml2/acs HTTP/1.1
Host: sp.example.com
Content-Type: application/x-www-form-urlencoded
Cookie: sp-session-tracking=...

SAMLResponse=PHNhbWxwOlJlc3BvbnNlIHhtbG5zOnNhbWxwPSJ1cm46b2FzaXM6bmFtZXM6...
&RelayState=aHR0cHM6Ly9zcC5leGFtcGxlLmNvbS9kYXNoYm9hcmQ%3D
```

---

### Step 9: SP Validates and Establishes Session

```
✓ Base64-decode SAMLResponse
✓ Parse XML
✓ Status = Success  ✓
✓ Destination = "https://sp.example.com/saml2/acs"  ✓
✓ InResponseTo = "_adf43daj3..." matches pending request  ✓  → remove from pending list
✓ Assertion signature verified using IdP cert from metadata  ✓
✓ Issuer = "https://idp.example.com/saml2/idp/metadata"  ✓
✓ Conditions: NotBefore ≤ now < NotOnOrAfter  ✓
✓ Audience = "https://sp.example.com/saml2/metadata"  ✓
✓ SubjectConfirmationData Recipient matches ACS URL  ✓
✓ SubjectConfirmationData InResponseTo matches  ✓
✓ Assertion ID "_b07b804c-..." not in replay cache  ✓  → add to replay cache
✓ AuthnContextClassRef meets minimum requirement  ✓
→ Identity: NameID = _uid-e3b0c44298...
→ Role: Analyst
→ Email: shaheryar@example.com
→ Session established
```

```http
HTTP/1.1 302 Found
Location: https://sp.example.com/dashboard
Set-Cookie: sp_session=eyJhbGciOiJIUzI1NiJ9...; HttpOnly; Secure; SameSite=Lax
```

---

## 10. Security Deep Dive

### 10.1 XML Signature Wrapping (XSW)

XSW is the most serious and historically impactful SAML vulnerability class. It exploits the complexity of XMLDSig validation to make the SP process a **different assertion than the one that was signed**.

#### How It Works

The attack relies on the disconnect between:
- **What is signed:** The assertion referenced by the `<ds:Reference URI="#assertion-id">`
- **What is processed:** The assertion element the SP's application code actually reads

An attacker who captures a valid SAML Response with a legitimate signed assertion for themselves can manipulate the XML to inject a forged assertion while keeping the valid signature intact.

**Attack variants (XSW1 through XSW8):**

The core technique: insert a second `<saml:Assertion>` element with forged attributes (e.g., attacker sets `NameID` to `admin@target.com`) and move the legitimate signed assertion to a location the SP's XPath query does not process (e.g., inside an `<Extensions>` element or as a sibling with a different ID).

```xml
<samlp:Response ...>
  <!-- FORGED assertion — not signed, but processed by some SP implementations -->
  <saml:Assertion ID="_forged" ...>
    <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>
    <saml:Subject>
      <saml:NameID>admin@target.com</saml:NameID>  <!-- attacker's desired identity -->
    </saml:Subject>
    <!-- ... conditions, authn statement etc. copied from legitimate assertion ... -->

    <!-- LEGITIMATE signed assertion embedded as a child (will be found by signature verifier) -->
    <saml:Advice>
      <saml:Assertion ID="_legitimate" ...>
        <saml:Issuer>https://idp.example.com/saml2/idp/metadata</saml:Issuer>
        <ds:Signature>
          <!-- Valid signature over _legitimate -->
        </ds:Signature>
        <saml:Subject>
          <saml:NameID>attacker@example.com</saml:NameID>  <!-- attacker's real identity -->
        </saml:Subject>
        <!-- ... -->
      </saml:Assertion>
    </saml:Advice>
  </saml:Assertion>
</samlp:Response>
```

If the SP:
1. Validates the signature (finds `_legitimate`, signature checks out ✓)
2. Processes the assertion (retrieves the first `<saml:Assertion>` it finds → `_forged`)

...the attacker authenticates as `admin@target.com`.

#### Impact

Complete authentication bypass. Attacker can authenticate as any user — including administrators — at the SP.

#### Mitigation

- The SP must use the `ID` from the validated `<ds:Reference URI>` to locate the assertion to process — not just "find any assertion element"
- Use well-maintained SAML libraries (ruby-saml ≥ 1.7.0, OneLogin's python-saml, Shibboleth SP) — many historical vulnerabilities were in custom or outdated parsers
- Reject responses with multiple assertion elements
- Validate the assertion ID referenced in the signature matches exactly one assertion
- Use schema validation before processing to reject unexpected structures

---

### 10.2 Assertion Replay Attacks

A captured valid assertion is replayed against the SP — potentially after the original user has logged out.

#### How It Works

```
1. Attacker captures a SAML Response (from logs, browser history, network interception)
2. Assertion is still within its validity window (NotOnOrAfter not yet reached)
3. Attacker POSTs the captured SAMLResponse to the SP's ACS URL
4. SP without replay detection accepts the valid, signed assertion
5. Attacker is authenticated as the assertion's subject
```

Particularly effective against IdP-initiated flows (no `InResponseTo` to verify).

#### Impact

Session hijacking; authentication bypass; continued access after the legitimate user has logged out.

#### Mitigation

- **Assertion ID cache:** Maintain a short-term cache of processed assertion IDs. Reject any assertion whose ID has already been seen. Cache entries must be retained until at least `NotOnOrAfter`.
- **Short validity windows:** Keep `NotOnOrAfter` to 2–5 minutes. Smaller windows reduce the replay opportunity.
- **`InResponseTo` validation:** For SP-initiated flows, validate `InResponseTo` and mark the referenced `AuthnRequestId` as consumed (single-use).

---

### 10.3 Improper Signature Validation

Accepting assertions with invalid, absent, or incorrectly applied signatures.

#### Attack Scenarios

- **No signature check:** SP parses the assertion and trusts it without verifying any signature.
- **Signature check bypassed by error handling:** An exception during signature verification is caught and suppressed, with the assertion accepted on the `catch` path.
- **Checking the wrong element:** SP verifies the signature over the `<samlp:Response>` but not over the `<saml:Assertion>` — an attacker can swap the assertion within a validly-signed response envelope.
- **Accepting `None` algorithm:** Similar to `alg=none` in JWT — some implementations accept `<ds:SignatureMethod Algorithm=""/>` or omit signature checking for unsigned assertions.

#### Mitigation

- `WantAssertionsSigned=true` in SP metadata — and enforce it
- Explicitly require assertion-level signatures, not just response-level
- Signature verification failure must be a hard rejection, never silently swallowed
- Validate the signing certificate against pre-registered IdP metadata — never trust an unknown certificate from `ds:KeyInfo`

---

### 10.4 Weak Certificate Validation

Using the certificate embedded in the assertion's `ds:KeyInfo` to verify the signature — without checking it against the pre-registered IdP certificate.

#### How It Works

```
1. Attacker generates a new self-signed X.509 certificate
2. Signs a forged assertion with the corresponding private key
3. Embeds the self-signed certificate in ds:KeyInfo
4. SP extracts the certificate from ds:KeyInfo and uses it to verify — it passes
5. SP trusts the forged assertion
```

#### Impact

Complete authentication bypass — attacker can assert any identity.

#### Mitigation

- **Never use the certificate from `ds:KeyInfo` as the trust anchor**
- The SP must maintain a whitelist of trusted IdP certificates from pre-registered metadata
- The certificate in `ds:KeyInfo` may be used to identify which key to use (if the IdP has multiple), but must be matched against the trusted certificate from metadata — not trusted on its own
- Reject signatures from unknown or unexpected certificates immediately

---

### 10.5 RelayState Manipulation and Open Redirect

`RelayState` is unsigned and travels through the browser. SPs that use it as a redirect target without validation are vulnerable.

#### How It Works

```
1. Attacker crafts a SAML flow with RelayState=https://attacker.com/phishing
2. If SP redirects to RelayState after successful authentication without validation:
   → User is redirected to attacker.com after login
   → Appears to originate from a trusted domain (sp.example.com)
   → Used for phishing, credential theft, OAuth token stealing in chained attacks
```

#### Mitigation

- Validate `RelayState` is a relative URL or an absolute URL on the SP's own domain
- Whitelist allowed redirect targets, or use an internal mapping (store the URL server-side and use an opaque token as RelayState)
- Never redirect to arbitrary external URLs from RelayState

---

### 10.6 IdP-Initiated Flow Abuse

The absence of `InResponseTo` in IdP-initiated assertions creates multiple attack surfaces.

#### Attack 1: Assertion Injection

An attacker who can obtain a valid assertion for themselves (e.g., by legitimately authenticating) can replay it at the SP's ACS endpoint at any time within the validity window, without having initiated a flow from that SP.

#### Attack 2: Phishing via IdP-Initiated URL

IdP-initiated flows are typically triggered by a URL like:
```
https://idp.example.com/app/saml2/myapp/launch
```

An attacker sends this URL to a victim. When the victim clicks it (while logged in to the IdP), they are transparently SSO'd into the application — potentially into a session the attacker can observe or into an account the attacker has prepared.

#### Mitigation

- Disable IdP-initiated SSO entirely for high-security applications if possible
- If IdP-initiated must be supported, implement strict assertion ID replay detection
- Verify the `RelayState` against a whitelist
- Some SPs require that IdP-initiated assertions still reference a recent pre-registered RelayState value — preventing fully unsolicited delivery

---

### 10.7 Lack of Audience Restriction Validation

An SP that does not check `<AudienceRestriction>` will accept assertions intended for any other SP at the same IdP.

#### How It Works

```
1. Attacker legitimately authenticates at an IdP as attacker@example.com
2. IdP issues an assertion with Audience="https://harmless-sp.example.com"
3. Attacker replays this assertion to "https://sensitive-sp.example.com/saml2/acs"
4. If sensitive-sp doesn't check Audience, it accepts the assertion
5. Attacker is authenticated at sensitive-sp as attacker@example.com
```

Combined with the ability to control the `NameID` (e.g., if `emailAddress` format is used and the attacker controls an email), this can escalate to authenticating as a privileged user at the target SP.

#### Mitigation

- Always validate `AudienceRestriction` — this is mandatory per the SAML 2.0 specification
- Reject assertions where the SP's own entityID is not present in `<saml:Audience>`
- This check is a required step in every compliant SAML implementation

---

### 10.8 XML External Entity (XXE) Injection

SAML messages are XML. XML parsers that process external entity declarations (`<!DOCTYPE ... <!ENTITY ...>`) are vulnerable to XXE attacks.

#### How It Works

An attacker crafts a SAML response with a malicious `DOCTYPE` declaration:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE samlp:Response [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<samlp:Response ...>
  ...
  <saml:AttributeValue>&xxe;</saml:AttributeValue>
  ...
</samlp:Response>
```

If the XML parser processes external entities, it will attempt to fetch `file:///etc/passwd` and include its content in the parsed document. The SP may then return this content in an error message, log it, or process it in other ways — resulting in local file disclosure, SSRF, or DoS.

#### Impact

- Local file read (credentials, keys, configuration files)
- SSRF (fetching internal network resources via HTTP entities)
- Denial of service (billion laughs attack via recursive entity expansion)

#### Mitigation

- **Disable external entity processing in the XML parser** — this is the primary control
- In Java: `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
- In Python (lxml): use `resolve_entities=False` and `no_network=True`
- Schema-validate the XML before processing — reject non-conforming documents
- Use a well-maintained SAML library rather than raw XML parsing

---

### 10.9 XML Canonicalization Confusion

Incorrect canonicalization during signature verification can lead to a bypass where a modified assertion appears to have a valid signature.

Specifically: if the SP verifies the signature using a different canonicalization algorithm than the one specified in `CanonicalizationMethod`, the computed digest may differ from the stored `DigestValue`. An attacker can exploit this if the SP falls back to a less strict canonicalization when the primary one fails — causing a valid signature check on a modified document.

#### Mitigation

- Use only the canonicalization algorithm specified in `CanonicalizationMethod`
- Do not fall back to alternative algorithms on verification failure
- Use audited XMLDSig libraries — this complexity is why hand-rolling is dangerous

---

## 11. Best Practices and Modern Guidance

### 11.1 Signature Validation (Strict)

```
□ Always require and validate assertion-level signatures
□ Reject responses where the assertion is not individually signed
□ Validate using certificate from pre-registered IdP metadata only
□ Never trust the X509Certificate in ds:KeyInfo as the sole trust anchor
□ Reject unsupported or weak signature algorithms (SHA-1, MD5)
□ Require RSA-SHA256 or ECDSA-SHA256 minimum
□ Verify the Reference URI matches the assertion being processed
□ Process only the specifically-referenced, signature-verified element
```

### 11.2 Always Validate Conditions and Audience

```
□ Check NotBefore (with ≤5 minute clock skew)
□ Check NotOnOrAfter (with ≤5 minute clock skew)
□ Check AudienceRestriction contains SP's entityID
□ Check SubjectConfirmationData Recipient matches ACS URL
□ Check SubjectConfirmationData NotOnOrAfter
□ Check InResponseTo matches a pending, unconsumed AuthnRequest ID
□ Maintain an assertion ID replay cache (min retention = NotOnOrAfter duration)
```

### 11.3 Secure Metadata Handling

- Fetch IdP metadata over HTTPS only
- Validate metadata signature if the IdP signs its metadata
- Check `validUntil` on metadata — reject expired metadata
- Implement a metadata refresh process — do not let metadata become stale
- For enterprise federations: use a metadata aggregator (e.g., eduGAIN, federation operators) with signed aggregate metadata

### 11.4 Avoid Insecure Bindings and Configurations

- Use HTTP POST binding for responses (never HTTP GET for SAMLResponse)
- Do not use HTTP Artifact binding unless specifically required (SOAP dependency adds complexity)
- Disable IdP-initiated SSO unless there is a specific operational requirement
- Require signed AuthnRequests (`WantAuthnRequestsSigned=true` in IdP metadata)
- Disable `AllowCreate=false` if the IdP should not provision new accounts automatically

### 11.5 XML Parser Hardening

```
□ Disable external entity (XXE) processing
□ Disable entity expansion (prevent billion laughs)
□ Schema-validate all incoming SAML messages against SAML 2.0 XSD
□ Reject documents with unexpected elements or structures
□ Set a maximum document size limit
□ Use battle-tested XML parsers with known security histories
```

### 11.6 When to Prefer OIDC over SAML

| Scenario | Recommendation |
|---|---|
| New greenfield web/mobile application | **OIDC** — simpler, JSON-based, rich library support |
| API authorization alongside authentication | **OIDC + OAuth 2.0** — SAML has no equivalent for API access delegation |
| Mobile clients (iOS, Android) | **OIDC** — SAML's browser-redirect model is awkward for native apps |
| Enterprise customer SSO mandate | **SAML** — legacy requirement; most enterprise IdPs mandate it |
| Government/regulated sector with existing SAML infrastructure | **SAML** — contractual or compliance requirements |
| Modern cloud-native identity (Azure AD, Okta, Google) | **OIDC** — all major providers prefer OIDC for new integrations |
| Complex attribute assertion with cryptographic guarantees | **SAML** — richer attribute framework; OIDC claims are simpler |

In practice, production SaaS applications often support **both** — OIDC for modern deployments and SAML for enterprise customers with legacy requirements.

### 11.7 Hardening Checklist

```
SP Configuration:
□ WantAssertionsSigned=true
□ AuthnRequestsSigned=true
□ Strict redirect URI validation (ACS URL in metadata must be exact)
□ Replay detection enabled (assertion ID cache)
□ Audience validation enforced
□ Conditions time validation enforced (with bounded clock skew)
□ InResponseTo validation for SP-initiated flows
□ XXE protection in XML parser
□ Schema validation of incoming messages
□ RelayState redirect validation (no open redirect)

IdP Configuration:
□ WantAuthnRequestsSigned=true (require signed AuthnRequests from SPs)
□ Short assertion validity windows (2–5 minutes)
□ EncryptedAssertion for sensitive deployments
□ Certificate rotation process documented and tested
□ Restrict ACS URLs to registered values only (no wildcard matching)
□ Log all SSO events with sufficient detail for forensic analysis
```

---

## Quick Reference

```
SAML 2.0 ACTORS:
  Identity Provider (IdP)    → authenticates users, issues assertions
  Service Provider (SP)      → consumes assertions, grants access
  Principal (User)           → whose identity is being asserted

CORE ARTIFACT:
  SAML Assertion (XML)       → signed XML document asserting identity + attributes
  Contains:
    Issuer                   → IdP entity ID
    Subject (NameID)         → who the assertion is about
    Conditions               → time window + AudienceRestriction
    AuthnStatement           → when/how the user authenticated + SessionIndex
    AttributeStatement       → user attributes (role, email, etc.)

TRANSPORT:
  HTTP Redirect Binding      → DEFLATE + Base64 + URL-encode → query parameter
  HTTP POST Binding          → Base64 → hidden form field → auto-submit
  HTTP Artifact Binding      → opaque reference + back-channel SOAP resolution

TRUST MODEL:
  X.509 certificates         → pre-registered, out-of-band, self-signed acceptable
  SAML Metadata              → XML document describing endpoints + certificates
  Signature algorithm        → XMLDSig (RSA-SHA256 minimum)

CRITICAL VALIDATION STEPS:
  ✓ StatusCode = Success
  ✓ Destination matches ACS URL
  ✓ InResponseTo matches pending AuthnRequest
  ✓ Assertion signature valid (using metadata certificate)
  ✓ Issuer matches expected IdP entityID
  ✓ NotBefore ≤ now < NotOnOrAfter
  ✓ Audience contains SP entityID
  ✓ SubjectConfirmationData Recipient and NotOnOrAfter
  ✓ Assertion ID not in replay cache
  ✓ AuthnContextClassRef meets minimum requirement

CRITICAL SECURITY RULES:
  → Never trust X509Certificate from ds:KeyInfo alone
  → Always validate AudienceRestriction
  → Always maintain assertion ID replay cache
  → Disable XXE in XML parser
  → Verify what was signed = what is processed (XSW prevention)
  → Validate RelayState before redirecting
  → Prefer OIDC for new applications
```

---

## References

- [SAML 2.0 Core Specification (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf)
- [SAML 2.0 Bindings Specification (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-bindings-2.0-os.pdf)
- [SAML 2.0 Profiles Specification (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-profiles-2.0-os.pdf)
- [SAML 2.0 Metadata Specification (OASIS)](https://docs.oasis-open.org/security/saml/v2.0/saml-metadata-2.0-os.pdf)
- [XML Digital Signature Syntax and Processing (W3C XMLDSig)](https://www.w3.org/TR/xmldsig-core/)
- [XML Encryption Syntax and Processing (W3C)](https://www.w3.org/TR/xmlenc-core/)
- [OWASP — SAML Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SAML_Security_Cheat_Sheet.html)
- [OWASP — XML Security — XXE Prevention](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
- [Duo Security — 8 XSW Attack Variants](https://duo.com/blog/saml-vulnerabilities-in-single-sign-on)
- [PortSwigger — SAML-Based Vulnerabilities](https://portswigger.net/web-security/authentication/other-mechanisms/saml)
- [NIST SP 800-63C — Digital Identity Guidelines: Federation and Assertions](https://pages.nist.gov/800-63-3/sp800-63c.html)
