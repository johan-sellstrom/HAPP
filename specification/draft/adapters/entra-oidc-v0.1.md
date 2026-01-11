# HAPP Identity Binding Adapter: Microsoft Entra OIDC (entra_oidc) v0.1

**Status:** Draft  
**Adapter ID:** `entra_oidc`  
**Applies to:** HAPP v0.3.x

## 1. Purpose

This adapter defines how a Presence Provider (PP) binds a HAPP consent event to a **Microsoft Entra ID** enterprise identity using OpenID Connect.

The normalized identity subject for this scheme is:
- `tid` (tenant id)
- `oid` (user object id)

## 2. Inputs (RP policy)

Within `requirements.identity`:

- `mode`: `none | preferred | required`
- `schemes`: includes `"entra_oidc"`
- `policy` keys (recommended):
  - `allowedTenants`: array of tenant ids allowed
  - `requireMfa`: boolean
  - `requiredAuthContexts`: array of auth context ids (e.g., ["c1"])
  - `requireEmbeddedEvidence`: boolean (embed ID token)

## 3. Protocol (PP side)

### 3.1 OIDC flow

PP SHOULD use:
- Authorization Code Flow with PKCE
- `nonce` binding
- `state` binding

Recommended endpoints:
- Authorization endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize`
- Token endpoint: `https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token`

### 3.2 Token validation

PP MUST validate:
- JWT signature (RS256 typically)
- `iss` matches expected issuer for the tenant / v2 endpoint
- `aud` matches PP’s Entra client id
- `exp`/`nbf`/`iat`
- `nonce` matches the authorization request

### 3.3 Subject normalization

PP MUST output:

```json
"identityBinding": {
  "mode": "verified",
  "scheme": "entra_oidc",
  "idp": {
    "issuer": "...",
    "tenantId": "<tid>"
  },
  "subject": {
    "type": "entra_oid_tid",
    "tid": "<tid>",
    "oid": "<oid>"
  }
}
```

### 3.4 Optional assurance signals

If present, PP SHOULD propagate:
- `auth_time`
- `amr`
- `acrs` / auth context indicators

If policy requires MFA or auth contexts, PP MUST enforce them.

### 3.5 Evidence embedding

If `requireEmbeddedEvidence=true`, PP MUST embed:
- the ID token (and optionally JWKS reference or JWK thumbprint)
and mark `identityBinding.evidence.embedded=true`.

If embedding is not required, PP MAY include only:
- `tokenHash`
- `nonceHash`
and rely on PP signature + certification.

## 4. Verification (RP side)

If RP requires identity binding, RP MUST:
- verify PP signature + trust
- verify `identityBinding.scheme == "entra_oidc"`
- verify `tid+oid` match the RP’s authenticated user identity

If RP requires embedded evidence, RP MUST:
- verify the embedded ID token signature (using JWKS),
- verify `nonce` / `nonceHash` binding,
- enforce tenant restrictions and any required assurance conditions.

