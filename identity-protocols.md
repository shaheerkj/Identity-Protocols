# Identity Protocols

Identity protocols standardize how users interact with systems and how they are verified. They give assertions about the user and what actions the user is allowed to perform. These protocols define how apps and organization lets users access and modify resources.



### Key terminologies:

- **Identity Provider (IdP)** → authenticates users
- **Service Provider (SP) / Relying Party (RP)** → consumes identity
- **Tokens/Assertions** → portable proof of identity/permissions
- **Claims** → user attributes (email, name, roles)
- **Scopes** → what access is being requested



The three major identity protocols are SAML, OIDC & OAuth2.0. We will be diving into these protocols today.

#### Simple Overview:

| Protocol  | Purpose        | Token type     | Common use         |
| --------- | -------------- | -------------- | ------------------ |
| OAuth 2.0 | Authorization  | Access token   | APIs, integrations |
| OIDC      | Authentication | ID token (JWT) | Modern login       |
| SAML      | Authentication | XML assertion  | Enterprise SSO     |

# OAuth2.0:

It's the most widely used industry-standard Authorization Framework. The official documentation for it can be found [here]([OAuth 2.0 &mdash; OAuth](https://oauth.net/2/)). 

In traditional client-server model, client requests an access-restricted resource on the server by authenticating with the server using the resource owner's credentials, which is unsafe for multitude of reasons. **OAuth** addresses this by providing an authorization layer.

In OAuth, the client requests access to resources controlledby the resource owner and hosted by the resource server, and is issued a different set of credentials than those of the resource owner.

Example: **End User**(Resource Owner) can grant a **printing service** (Client) access to files that need to be printed, which are stored in a **sharing service** (Resource Server), without sharing her credentials directly. Instead, she authenticates directly with the **sharing service** (Authorization Server), which issues the printing service **delegation-specific credentials** (Access tokens.)

### Roles:

4 main roles are defined in OAuth2.0

- <u>Resource Owner</u>: Entity capable of granting access to a protected resource (End-user).

- <u>Resource Server</u>: Server hosting the protected resources, capable of accepting and responding to protected resource requests using access tokens.

- <u>Client</u>: Application making protected resource requests on behalf of the resource owner and its authorization.

- <u>Authorization Server</u>: The server issuing the access tokens.



### Flow:

The Abstract flow:



```textile
     +--------+                               +---------------+
     |        |--(A)- Authorization Request ->|   Resource    |
     |        |                               |     Owner     |
     |        |<-(B)-- Authorization Grant ---|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(C)-- Authorization Grant -->| Authorization |
     | Client |                               |     Server    |
     |        |<-(D)----- Access Token -------|               |
     |        |                               +---------------+
     |        |
     |        |                               +---------------+
     |        |--(E)----- Access Token ------>|    Resource   |
     |        |                               |     Server    |
     |        |<-(F)--- Protected Resource ---|               |
     +--------+                               +---------------+
```

**(A)** Client requests authorization from the resource owner (directly or via the authorization server).  
**(B)** Resource owner grants authorization; client receives an authorization grant. Which can one of 4 grant types, will be discussed later. 
**(C)** Client sends the grant to the authorization server to request an access token.  
**(D)** Authorization server validates the grant (and client), then issues an access token.  
**(E)** Client uses the access token to request the protected resource from the resource server.  
**(F)** Resource server validates the token and returns the requested resource.



### Authorization Grant:

Authorization Grant is a credential representing the resource owner's authorization, used by the client to obtain an access token. Can be one of four types:

**1. Authorization Code (most secure, common)**

- Client redirects user to authorization server.
- User logs in and approves access.
- Server returns an **authorization code** to client.
- Client exchanges code for an **access token**.
- **Benefit:** User credentials never reach the client; safer and supports client authentication.

**2. Implicit (simplified, browser apps)**

- Access token is returned directly after user login/approval.
- No authorization code step.
- **Benefit:** Faster, fewer steps.
- **Downside:** Less secure—token exposed to browser and user-agent; client not authenticated.

**3. Resource Owner Password Credentials**

- User directly gives username/password to client.
- Client exchanges them for an access token.
- **Use only when high trust exists** (e.g., official OS app).
- **Downside:** Client handles user credentials directly (risky).

**4. Client Credentials**

- Client authenticates itself (no user involved).
- Used for machine-to-machine access or client-owned resources.
- **Best for:** backend services, server-to-server communication.



### Access Token:

Access tokens are credentials used to access protected resources.  An access token is a string representing an authorization issued to the client.  The string is usually opaque to the client.  Tokens represent specific scopes and durations of access, granted by the resource owner, and enforced by the resource server and authorization server.Access tokens are credentials used to access protected resources.  An access token is a string representing an authorization issued to the client.  The string is usually opaque to the client.  Tokens represent specific scopes and durations of access, granted by the resource owner, and enforced by the resource server and authorization server.



### Refresh Token:

Refresh tokens are credentials used to obtain access tokens.  Refresh tokens are issued to the client by the authorization server and are used to obtain a new access token when the current access token becomes invalid or expires, or to obtain additional access tokens with identical or narrower scope (access tokens may have a shorter lifetime and fewer permissions than authorized by the resource owner).  Issuing a refresh token is optional at the discretion of the authorization server.  If the authorization server issues a refresh token, it is included when issuing an access token

refreshing an expired token:

```textile
  +--------+                                           +---------------+
  |        |--(A)------- Authorization Grant --------->|               |
  |        |                                           |               |
  |        |<-(B)----------- Access Token -------------|               |
  |        |               & Refresh Token             |               |
  |        |                                           |               |
  |        |                            +----------+   |               |
  |        |--(C)---- Access Token ---->|          |   |               |
  |        |                            |          |   |               |
  |        |<-(D)- Protected Resource --| Resource |   | Authorization |
  | Client |                            |  Server  |   |     Server    |
  |        |--(E)---- Access Token ---->|          |   |               |
  |        |                            |          |   |               |
  |        |<-(F)- Invalid Token Error -|          |   |               |
  |        |                            +----------+   |               |
  |        |                                           |               |
  |        |--(G)----------- Refresh Token ----------->|               |
  |        |                                           |               |
  |        |<-(H)----------- Access Token -------------|               |
  +--------+           & Optional Refresh Token        +---------------+
```


