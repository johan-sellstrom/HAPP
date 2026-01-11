# HAPP Conformance v0.3 (Draft)

**Status:** Draft  
**Applies to:** HAPP v0.3.x (including v0.3.4 bundle)

This document defines conformance classes and testable requirements (MUST/SHOULD) for:
- Presence Providers (PP)
- Relying Parties (RP)
- Identity Binding adapters (initial: `entra_oidc`)

## Conformance classes

- **HAPP-PP-0.3**: Presence Provider core (PoHP + intent binding)
- **HAPP-RP-0.3**: Relying Party verifier core
- **HAPP-PP-ID-0.3**: Presence Provider identity binding support
- **HAPP-RP-ID-0.3**: Relying Party identity binding verification
- **HAPP-ADAPTER-entra_oidc-0.1-PP**: PP implementing Entra OIDC adapter
- **HAPP-ADAPTER-entra_oidc-0.1-RP**: RP verifying Entra OIDC adapter

## PP core requirements (HAPP-PP-0.3)

- **PP-CORE-01 (MUST)** Validate AI-INTENT schema and compute `intent_hash` from canonicalized AI-INTENT.
- **PP-CORE-02 (MUST)** Derive Signing View and compute `presentation_hash`.
- **PP-CORE-03 (MUST)** Display the Signing View (or equivalent deterministic rendering) to the human in the PP UI.
- **PP-CORE-04 (MUST)** Issue HAPP-CC containing `intent_hash`, `presentation_hash`, `aud`, `jti`, `iat`, `exp`, `assurance`.
- **PP-CORE-05 (MUST)** Do not include biometric samples in HAPP-CC.
- **PP-CORE-06 (MUST)** Include provider certification evidence (embedded or referenced) sufficient for RP to check PoHP level validity.

## RP core requirements (HAPP-RP-0.3)

- **RP-CORE-01 (MUST)** Verify HAPP-CC signature and issuer trust.
- **RP-CORE-02 (MUST)** Verify `aud` matches RP context.
- **RP-CORE-03 (MUST)** Enforce expiry and max age policy.
- **RP-CORE-04 (MUST)** Recompute and match `intent_hash`.
- **RP-CORE-05 (MUST)** Recompute and match `presentation_hash`.
- **RP-CORE-06 (MUST)** Enforce minimum PoHP level and validate provider certification.
- **RP-CORE-07 (MUST)** Enforce one-time use when required (`jti` replay prevention).
- **RP-CORE-08 (MUST)** Enforce envelope constraints when present.

## PP identity binding requirements (HAPP-PP-ID-0.3)

- **PP-IDB-01 (MUST)** Support `requirements.identity` input.
- **PP-IDB-02 (MUST)** If `mode="required"` and identity cannot be satisfied, PP MUST NOT issue HAPP-CC.
- **PP-IDB-03 (MUST)** If identity performed, include `claims.identityBinding` with `mode`, `scheme`, `subject`.
- **PP-IDB-04 (MUST)** Bind identity evidence to the same approval session as PoHP (single consent event).
- **PP-IDB-05 (MUST)** If `requireEmbeddedEvidence=true`, embed evidence and mark it embedded.
- **PP-IDB-06 (SHOULD)** Minimize PII; prefer stable subject identifiers over display names/emails.

## RP identity binding requirements (HAPP-RP-ID-0.3)

- **RP-IDB-01 (MUST)** If identity required, reject HAPP-CC missing identityBinding.
- **RP-IDB-02 (MUST)** Enforce scheme allow-list and required identity mode.
- **RP-IDB-03 (MUST)** Verify identityBinding subject matches RP account/session identity.
- **RP-IDB-04 (MUST when required)** If embedded evidence required, verify embedded evidence per scheme rules.
- **RP-IDB-05 (SHOULD)** Enforce identity freshness when `auth_time` is present.

## Entra adapter requirements (PP) — HAPP-ADAPTER-entra_oidc-0.1-PP

- **ENTRA-PP-01 (MUST)** Use OIDC Authorization Code + PKCE (session-bound).
- **ENTRA-PP-02 (MUST)** Validate ID token signature and core claims: `iss`, `aud`, `exp`, `iat/nbf`.
- **ENTRA-PP-03 (MUST)** Validate nonce binding and output `nonceHash`.
- **ENTRA-PP-04 (MUST)** Normalize subject as `tid+oid` and output `subject.type="entra_oid_tid"`.
- **ENTRA-PP-05 (MUST when provided)** Enforce `allowedTenants`.
- **ENTRA-PP-06 (MUST when required)** Enforce MFA/auth context requirements when requested by RP policy.

## Entra adapter requirements (RP) — HAPP-ADAPTER-entra_oidc-0.1-RP

- **ENTRA-RP-01 (MUST)** Verify `tid+oid` match the RP’s authenticated Entra user (or mapping).
- **ENTRA-RP-02 (MUST when required)** If embedded evidence is present and policy requires, verify signature and claims.

