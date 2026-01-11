# Enterprise integration: Microsoft Entra identity binding (entra_oidc)

HAPP supports **optional, policy-driven identity binding** in addition to Proof of Human Presence (PoHP).

In enterprise contexts, relying parties often require that the approving human is a specific corporate identity (for example, the Entra user authenticated to the enterprise application), not just “some live human”.

## How it works

1. The relying party issues a HAPP Challenge (HAPP-CHAL) that includes:
   - a minimum PoHP level (e.g., AAIF-PoHP-3)
   - `identity.mode` (none | preferred | required)
   - acceptable `identity.schemes` (e.g., `entra_oidc`)
   - optional scheme policy (allowed tenant IDs, MFA requirement, authentication context)

2. The Presence Provider performs:
   - PoHP (liveness + explicit approval), and
   - Entra OIDC sign-in (Authorization Code + PKCE + nonce)

3. The Presence Provider issues a Consent Credential (HAPP-CC) that binds:
   - `intent_hash` (what will execute)
   - `presentation_hash` (what was displayed for consent)
   - PoHP assurance level
   - `identityBinding.scheme=entra_oidc` with a normalized subject (`tid` + `oid`)
   - optional embedded evidence (Entra ID token) when the relying party requires self-verifiable evidence

4. The relying party verifies:
   - provider signature and certification evidence
   - hashes and audience binding
   - PoHP level meets policy
   - identity subject matches the relying party’s session identity (tenant + user object id)
   - evidence meets policy (nonce binding, MFA/auth context, tenant allow-list)

## Why `tid` + `oid`

The Entra adapter normalizes identity as `tid` (tenant id) + `oid` (user object id) so relying parties can use stable identifiers for authorization decisions.

## Common adapter policy keys

- `allowedTenants`: restrict acceptable Entra tenants
- `requireMfa`: require proof of MFA
- `requiredAuthContexts`: require specific authentication context(s)
- `requireEmbeddedEvidence`: require the ID token to be embedded so the relying party can verify it directly
- `maxIdAgeSeconds`: identity freshness window based on `auth_time`
