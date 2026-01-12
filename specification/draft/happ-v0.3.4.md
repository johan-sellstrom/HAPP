# HAPP v0.3.4 — Human Authorization & Presence Protocol (Draft)

**Status:** Draft  
**Version:** 0.3.4  
**Track:** AAIF Standards / MCP Profile

## 1. Abstract

HAPP (Human Authorization & Presence Protocol) standardizes how an agentic system obtains **explicit human authorization** for a **machine-readable Action Intent**, optionally binds that authorization to a **verified identity**, and produces a **portable, verifiable Consent Credential** that a relying party can validate and audit.

HAPP is designed to be:
- **Vendor-neutral** (multiple certified Presence Providers can implement it),
- **Deployable today** (as an MCP tool profile + URL-mode consent UI),
- **Policy-driven** (Relying Parties decide whether PoHP alone is sufficient, or identity binding is also required),
- **Deepfake-aware** (PoHP assurance levels and certification evidence).

## 2. Motivation

Agents are moving from “assist” to “act” (payments, permissions, data deletion, account recovery). Traditional “consent prompts” are typically:
- UI-only and non-portable,
- difficult to audit,
- vulnerable to replay,
- vulnerable to UI/intent mismatch.

HAPP provides:
1) a deterministic **Action Intent** DSL,
2) a deterministic **Signing View** and **presentation_hash** (WYSIWYS: what you show is what you sign),
3) a portable **Consent Credential** (HAPP-CC),
4) optional **Identity Binding** (pluggable adapters),
5) a **Relying Party Challenge** pattern to enforce policy at the API boundary.

## 3. Goals and non-goals

### 3.1 Goals
HAPP v0.3.4 MUST:
- Support **Proof of Human Presence** (PoHP) with an assurance level.
- Bind authorization to the **exact intent** via `intent_hash`.
- Bind authorization to **what the human was shown** via `presentation_hash`.
- Support **optional identity binding** via adapter schemes, controlled by RP policy.
- Be implementable as an **MCP tool** with URL-mode consent UI.

### 3.2 Non-goals
HAPP does NOT:
- Define biometric algorithms.
- Require centralized biometric storage.
- Guarantee the human read/understood the content (it guarantees display + explicit approval).
- Replace transport/authN standards (OAuth/OIDC/WebAuthn); it composes with them.

## 4. Terminology

- **Human Principal:** natural person with authority over an agent’s actions.
- **Agent:** software acting on behalf of a principal.
- **Relying Party (RP):** service that executes an action and verifies proof.
- **Presence Provider (PP):** certified service that performs PoHP and issues HAPP-CC.
- **Action Intent (AI-INTENT):** canonical JSON describing the action to authorize.
- **Signing View (AAIF-SigningView):** deterministic object derived from AI-INTENT for display and hashing.
- **PoHP:** Proof of Human Presence with assurance level AAIF-PoHP-1..4.
- **HAPP Challenge (HAPP-CHAL):** RP-issued envelope requiring HAPP for an intent.
- **HAPP Consent Credential (HAPP-CC):** signed credential binding PoHP (+ optional identity) to intent_hash + presentation_hash + audience.
- **Identity Binding:** optional scheme that binds consent to an identity (e.g., Entra user `tid+oid`).

## 5. Data model overview

HAPP defines three primary objects:

1) **AI-INTENT** (Action Intent)  
2) **HAPP-CHAL** (Relying Party Challenge; optional but recommended for enforcement)  
3) **HAPP-CC** (Consent Credential)  

HAPP also defines:
- **HAPP-PCC** (Provider Certification Credential)

All objects are defined in JSON schemas under `/schemas`.

## 6. Action Intent (AI-INTENT) v0.3

### 6.1 Canonicalization and hashing

AI-INTENT MUST be canonicalized using **RFC 8785 (JCS)** prior to hashing.

`intent_hash = "sha256:" + base64url( SHA-256( UTF8( JCS(AI-INTENT) ) ) )`

### 6.2 Profiles

AI-INTENT SHOULD include a `profile` string. Profiles define:
- required parameters,
- “must-display” fields,
- Signing View construction rules.

If profile is absent or unknown, PP MUST use Generic Profile rules.

Known profiles:
- `ai_ui_confirm_v1` — AI UI confirmation / WYSIWYS profile ([ai-intent-profiles/ai-ui-confirm-v1.md](ai-intent-profiles/ai-ui-confirm-v1.md))

### 6.3 Envelopes (bounded flexibility)

AI-INTENT MAY include `constraints.envelope` describing allowed parameter ranges or allow-lists (e.g., amount range, allowed payees). If present:
- PP MUST include envelope constraints in the Signing View,
- RP MUST enforce envelope constraints at execution time.

If the action falls outside envelope constraints, a new AI-INTENT and new consent are required.

## 7. Signing View and presentation_hash (WYSIWYS)

### 7.1 Signing View

PP MUST derive a Signing View from AI-INTENT:
- using the declared profile rules if recognized, otherwise
- using Generic Profile rules that include:
  - audience identity,
  - agent identity,
  - action.type,
  - action.parameters (deterministic, complete),
  - constraints (expiry, maxUses/oneTime, envelope).

### 7.2 Presentation hash

Signing View MUST be canonicalized using JCS and hashed:

`presentation_hash = "sha256:" + base64url( SHA-256( UTF8( JCS(SigningView) ) ) )`

PP MUST include `presentation_hash` in HAPP-CC.
RP SHOULD recompute presentation_hash from AI-INTENT and compare.

## 8. Proof of Human Presence (PoHP)

PoHP assurance levels are defined in `pohp-assurance-levels-v0.3.md` and referenced by string:
- `AAIF-PoHP-1` .. `AAIF-PoHP-4`

RP policy determines minimum required level by action type.

## 9. Identity Binding (pluggable adapters)

### 9.1 Policy knob

RP MAY require identity binding. Requirements are expressed in:
- HAPP-CHAL `requirements.identity`, and/or
- MCP tool args `requirements.identity`.

Fields:
- `mode`: `"none" | "preferred" | "required"`
- `schemes`: array of acceptable identity schemes (adapter identifiers)
- `policy`: scheme-agnostic and scheme-specific options

If `mode="required"` and identity binding cannot be satisfied, PP MUST NOT issue HAPP-CC.

### 9.2 Identity binding block

If identity binding is satisfied, PP MUST include:

`claims.identityBinding = { mode, scheme, subject, idp, assurance?, evidence? }`

Where:
- `scheme` identifies the adapter (e.g., `entra_oidc`)
- `subject` is the normalized subject identifier for that adapter
- `evidence` MAY embed or reference verifiable evidence (e.g., OIDC ID token)

### 9.3 Adapter example: Microsoft Entra OIDC (`entra_oidc`)

The `entra_oidc` scheme binds consent to an Entra user identity represented by:
- `tid` (tenant id)
- `oid` (user object id)

Recommended normalization:
- `subject.type = "entra_oid_tid"`
- `subject.tid = <tid>`
- `subject.oid = <oid>`

Additional policy MAY require:
- MFA (`requireMfa`)
- authentication context (`requiredAuthContexts`)
- allowed tenants (`allowedTenants`)
- embedded evidence (`requireEmbeddedEvidence`)

See `adapters/entra-oidc-v0.1.md`.

## 10. Relying Party Challenge Mode (HAPP-CHAL)

An RP MAY enforce HAPP by returning a HAPP-CHAL to the client/agent when a request lacks sufficient authorization.

HAPP-CHAL MUST include:
- `challengeId`
- `expiresAt`
- `requirements` (PoHP + optional identity binding)
- `actionIntent`
- optional `rpProof` (signature over the challenge body)

If rpProof is present:
- PP MUST verify it prior to issuing HAPP-CC
- PP SHOULD display “Verified RP” to the user

## 11. Consent Credential (HAPP-CC)

HAPP-CC MUST:
- be signed by PP
- include:
  - `intent_hash`
  - `presentation_hash`
  - `aud` (RP identifier)
  - `jti`, `iat`, `exp`
  - `assurance` (PoHP)
  - provider certification evidence (embedded or referenced)
- optionally include:
  - `identityBinding` (if performed)
  - `challengeId` / challenge reference (if issued from HAPP-CHAL)

Credential formats:
- `jwt` (JWS)
- `vc+json` (VC Data Model with a proof)

## 12. Verification requirements (RP)

RP verifying HAPP-CC MUST:
1. Verify PP signature and trust (keys/registry).
2. Verify `aud` matches RP.
3. Verify `exp` and max credential age.
4. Recompute and match `intent_hash`.
5. Recompute and match `presentation_hash`.
6. Enforce PoHP minimum level.
7. Verify provider certification supports asserted PoHP level.
8. Enforce one-time use when required (`jti` replay).
9. Enforce envelope constraints (executed action within bounds).
10. If identity binding required:
    - enforce scheme allow-list
    - enforce subject match (e.g., Entra `tid+oid`)
    - enforce any scheme policies (MFA, auth contexts, allowed tenants)
    - if embedded evidence required, verify it.

## 13. MCP profile

HAPP can be implemented as an MCP tool:
- `aaif.happ.request`

URL-mode consent UI is used for sensitive interaction.
See `mcp-profile-v0.3.4.md`.

## 14. Security considerations

HAPP mitigates:
- UI mismatch (presentation_hash)
- replay (aud binding, TTL, jti)
- agent tampering (intent_hash; RP Challenge Mode)
- spoofing and deepfakes (PoHP levels + certification)

HAPP does not mitigate:
- compromised user devices
- coercion outside the protocol
- malware after authorization

## 15. Privacy considerations

- No biometric samples in HAPP-CC.
- Identity binding should use stable identifiers and minimize PII.
- Pairwise identifiers and selective disclosure are recommended for future versions.

## References
- RFC 8785 JSON Canonicalization Scheme: https://www.rfc-editor.org/rfc/rfc8785
- MCP Specification: https://modelcontextprotocol.io/specification/2025-11-25
