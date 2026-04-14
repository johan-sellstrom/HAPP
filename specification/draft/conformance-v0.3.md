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
- **HAPP-PROFILE-entra_claims_challenge-0.1-PP**: PP supporting Entra claims challenge transport
- **HAPP-PROFILE-entra_claims_challenge-0.1-RP**: RP / bridge consuming Entra claims challenge transport

## PP core requirements (HAPP-PP-0.3)

- **PP-CORE-01 (MUST)** Validate AI-INTENT schema and compute `intent_hash` from AI-INTENT canonicalized with RFC 8785 (JCS).
- **PP-CORE-02 (MUST)** Derive Signing View and compute `presentation_hash`.
- **PP-CORE-03 (MUST)** Display the Signing View (or equivalent deterministic rendering) to the human in the PP UI.
- **PP-CORE-04 (MUST)** Issue HAPP-CC containing `intent_hash`, `presentation_hash`, `aud`, `jti`, `iat`, `exp`, `assurance`.
- **PP-CORE-05 (MUST)** Do not include biometric samples in HAPP-CC.
- **PP-CORE-06 (MUST)** Include provider certification evidence (embedded or referenced) sufficient for RP to check PoHP level validity.
- **PP-CORE-07 (MUST)** If credential issuance is based on HAPP-CHAL input, include `claims.challengeId` and set it to the exact challenge used for the consent event.

## RP core requirements (HAPP-RP-0.3)

- **RP-CORE-01 (MUST)** Verify HAPP-CC signature and issuer trust.
- **RP-CORE-02 (MUST)** Verify `aud` matches RP context.
- **RP-CORE-03 (MUST)** Enforce expiry/max-age with bounded clock skew, including `exp`, `iat`, and `nbf` (if present).
- **RP-CORE-04 (MUST)** Recompute and match `intent_hash` using RFC 8785 (JCS) canonicalization of AI-INTENT.
- **RP-CORE-05 (MUST)** Recompute and match `presentation_hash` using RFC 8785 (JCS) canonicalization of Signing View.
- **RP-CORE-06 (MUST)** Enforce minimum PoHP level and validate provider certification.
- **RP-CORE-07 (MUST)** Enforce one-time use when required (`jti` replay prevention) with atomic consume semantics.
- **RP-CORE-08 (MUST)** Enforce envelope constraints when present.
- **RP-CORE-09 (MUST when challenge mode is used/policy-required)** Verify `claims.challengeId` exists, matches an outstanding challenge, is unexpired, and has not been consumed.
- **RP-CORE-10 (SHOULD)** Retain replay-cache state for consumed `jti`/`challengeId` entries until at least `exp + skew`.

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
- **ENTRA-PP-02 (MUST)** Validate ID token signature and core claims: `iss`, `aud`, `exp`, `iat/nbf`, with bounded clock skew.
- **ENTRA-PP-03 (MUST)** Validate nonce binding and output `nonceHash`.
- **ENTRA-PP-04 (MUST)** Normalize subject as `tid+oid` and output `subject.type="entra_oid_tid"`.
- **ENTRA-PP-05 (MUST when provided)** Enforce `allowedTenants`.
- **ENTRA-PP-06 (MUST when required)** Enforce MFA/auth context requirements when requested by RP policy.
- **ENTRA-PP-07 (MUST)** Keep OIDC nonce/session freshness state outside AI-INTENT payload semantics.

## Entra adapter requirements (RP) — HAPP-ADAPTER-entra_oidc-0.1-RP

- **ENTRA-RP-01 (MUST)** Verify `tid+oid` match the RP’s authenticated Entra user (or mapping).
- **ENTRA-RP-02 (MUST when required)** If embedded evidence is present and policy requires, verify signature and claims with bounded clock skew.
- **ENTRA-RP-03 (MUST when nonce evidence is present)** Verify nonce binding (`nonce` and/or `nonceHash`) for embedded Entra evidence.


## Entra claims challenge profile (PP) — HAPP-PROFILE-entra_claims_challenge-0.1-PP

- **ENTRA-CC-PP-01 (MUST)** Accept an explicit claims request via `requirements.identity.policy.entraClaimsChallenge` or `schemeParams.entra_claims_challenge` when present.
- **ENTRA-CC-PP-02 (SHOULD)** Derive a minimal Entra claims request from `requireMfa` and/or `requiredAuthContexts` when explicit challenge data is absent.
- **ENTRA-CC-PP-03 (MUST)** Send the effective Entra `claims` parameter on the Authorization Code + PKCE authorization request.
- **ENTRA-CC-PP-04 (MUST)** Keep `state`, `nonce`, PKCE, and the HAPP session bound together for the entire enterprise step-up flow.
- **ENTRA-CC-PP-05 (MUST)** Continue to issue a normal HAPP Consent Credential after the Entra step-up completes; the refreshed token alone is not sufficient.

## Entra claims challenge profile (RP/bridge) — HAPP-PROFILE-entra_claims_challenge-0.1-RP

- **ENTRA-CC-RP-01 (MAY)** Request enterprise step-up by providing explicit Entra claims-challenge data in policy.
- **ENTRA-CC-RP-02 (SHOULD)** Require embedded evidence when direct verification of the refreshed enterprise identity token is necessary.
- **ENTRA-CC-RP-03 (MUST)** Continue to verify the resulting HAPP Consent Credential in full, including identity binding, rather than relying on the refreshed token alone.
