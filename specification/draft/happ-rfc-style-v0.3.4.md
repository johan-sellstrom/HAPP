# HAPP v0.3.4 (RFC-Style Protocol Draft)

**Status:** Informational Draft  
**Intended status:** Community standardization input  
**Updates:** None  
**Obsoletes:** None

## 1. Status of This Memo

This document provides an RFC-style protocol rendering of HAPP v0.3.4 for implementers who prefer strict protocol language and verification procedures.

This document is not an IETF RFC. It uses BCP 14 key words for requirement clarity.

## 2. Abstract

HAPP (Human Authorization and Presence Protocol) allows an agentic system to obtain explicit human approval for a machine-readable action, bind that approval to proof-of-human-presence (PoHP), optionally bind enterprise identity, and deliver a portable consent credential for relying-party verification.

HAPP defines:
- AI-INTENT (action semantics),
- HAPP-CHAL (relying-party challenge envelope),
- HAPP-CC (consent credential).

## 3. Requirements Language

The key words "`MUST`", "`MUST NOT`", "`REQUIRED`", "`SHALL`", "`SHALL NOT`", "`SHOULD`", "`SHOULD NOT`", "`RECOMMENDED`", "`NOT RECOMMENDED`", "`MAY`", and "`OPTIONAL`" in this document are to be interpreted as described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear in all capitals.

## 4. Protocol Roles

- **Agent:** software initiating an action for approval.
- **Relying Party (RP):** execution boundary that enforces policy and verifies proofs.
- **Presence Provider (PP):** service that runs PoHP and issues HAPP-CC.
- **Human Principal:** natural person authorizing the action.

## 5. Data Objects

### 5.1 AI-INTENT

AI-INTENT is the canonical business action description.

AI-INTENT:
- `MUST` be structurally valid per schema.
- `MUST` be canonicalized with RFC 8785 JCS before hashing.
- `MUST NOT` embed per-session freshness secrets (for example OIDC `nonce`, OIDC `state`, callback one-time tokens).

Rationale: AI-INTENT represents stable semantics ("what"), while freshness belongs to challenge/session controls ("this attempt now").

### 5.2 HAPP-CHAL

HAPP-CHAL is an RP challenge envelope for strong step-up control.

HAPP-CHAL contains at minimum:
- `challengeId`,
- `expiresAt`,
- `requirements`,
- `actionIntent`,
- optional `rpProof`.

RP requirements:
- `challengeId` `MUST` be unique in RP scope.
- `challengeId` `MUST` be single-use.
- challenge lifetime `SHOULD` be short for high-risk operations.

### 5.3 HAPP-CC

HAPP-CC is the signed consent credential.

HAPP-CC claims `MUST` include:
- `intent_hash`,
- `presentation_hash`,
- `aud`,
- `jti`,
- `iat`,
- `exp`,
- PoHP assurance block.

HAPP-CC `MAY` include:
- `nbf`,
- `identityBinding`,
- `challengeId` (required when credential is challenge-derived).

If PP issued from HAPP-CHAL input, PP `MUST` include `claims.challengeId` equal to the challenge used for that consent event.

## 6. Canonicalization and Hashing

### 6.1 intent_hash

`intent_hash` is computed as:

`"sha256:" + base64url( SHA-256( UTF8( JCS(AI-INTENT) ) ) )`

### 6.2 presentation_hash

PP derives Signing View from AI-INTENT per profile rules (or generic profile), then computes:

`"sha256:" + base64url( SHA-256( UTF8( JCS(SigningView) ) ) )`

PP `MUST` include `presentation_hash` in HAPP-CC.

## 7. Protocol Operations

### 7.1 Agent-Initiated Mode

1. Agent sends AI-INTENT and policy requirements to PP tool endpoint.
2. PP returns URL-mode interaction if human interaction is required.
3. Human reviews Signing View and approves/denies.
4. PP issues HAPP-CC.
5. Agent presents HAPP-CC to RP.
6. RP verifies and executes only on success.

### 7.2 RP Challenge Mode

1. Agent attempts operation at RP boundary.
2. RP returns HAPP-CHAL when authorization proof is missing or insufficient.
3. Agent submits challenge to PP.
4. PP validates challenge context and obtains human approval.
5. PP issues HAPP-CC with matching `challengeId`.
6. Agent retries operation with HAPP-CC.
7. RP verifies HAPP-CC and atomically consumes challenge and replay state.

For high-risk actions, RP `SHOULD` require challenge mode.

### 7.3 Identity Binding Mode

If RP policy sets identity mode to `required`:
- PP `MUST NOT` issue HAPP-CC unless identity binding succeeds.
- PP `MUST` bind identity evidence to the same consent event as PoHP.

For Entra OIDC:
- nonce/state are session controls and `MUST NOT` be represented as AI-INTENT semantics.

## 8. RP Verification Procedure (Normative)

Given `(happ_cc, ai_intent, rp_policy, now)` RP performs:

1. Verify credential signature and issuer trust.
2. Verify `aud` equals RP context.
3. Validate time claims with bounded skew (`maxClockSkewSeconds`, `RECOMMENDED <= 300`):
   - reject if `now > exp + skew`,
   - if `nbf` present, reject if `now + skew < nbf`,
   - reject if `iat > now + skew`,
   - enforce max credential age from `iat` and RP policy.
4. Recompute `intent_hash` from AI-INTENT using RFC 8785 and require exact match.
5. Derive Signing View from same AI-INTENT, recompute `presentation_hash` with RFC 8785, require exact match.
6. Enforce minimum PoHP level and provider certification policy.
7. Enforce replay policy:
   - if one-time policy applies, `jti` `MUST` be unconsumed,
   - consume `jti` atomically with authorize/execute decision.
8. If RP policy expects challenge mode:
   - require `claims.challengeId`,
   - verify challenge exists, is unexpired, and unconsumed,
   - consume challenge atomically with execution.
9. Enforce envelope constraints from AI-INTENT.
10. If identity binding required:
   - enforce scheme allow-list,
   - verify subject match (for example Entra `tid+oid`),
   - verify embedded evidence if required by policy.

RP `MUST` reject malformed JSON prior to canonicalization (including duplicate member names).

## 9. Replay and Freshness Model

Freshness controls are layered:
- challenge freshness: `challengeId` + `expiresAt`,
- credential freshness: `iat`/`nbf`/`exp`,
- replay controls: `jti` and challenge single-use state.

RPs `SHOULD` retain consumed replay entries at least until `exp + skew`.

## 10. Error Handling

Implementations `SHOULD` return deterministic errors for:
- signature/trust failure,
- audience mismatch,
- expired/not-yet-valid token,
- hash mismatch,
- replay state conflict,
- challenge mismatch/consumption,
- identity policy failure.

Errors returned to untrusted callers `SHOULD` minimize sensitive policy leakage.

## 11. Security Considerations

HAPP addresses:
- UI/intent mismatch via `presentation_hash`,
- tampering via credential signatures,
- replay via challenge + `jti` + time bounds,
- weak human proof via PoHP assurance and certification.

HAPP does not eliminate:
- endpoint compromise,
- coercion outside protocol scope,
- post-authorization malware actions.

## 12. Privacy Considerations

- HAPP-CC `MUST NOT` embed raw biometric samples.
- Identity binding data `SHOULD` use stable low-PII identifiers.
- Evidence embedding `SHOULD` be policy-driven and minimized.

## 13. IANA Considerations

This document has no IANA actions.

## 14. References

### 14.1 Normative

- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels.
- RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119 Key Words.
- RFC 8785: JSON Canonicalization Scheme (JCS).
- HAPP core draft: `happ-v0.3.4.md`.
- HAPP MCP profile draft: `mcp-profile-v0.3.4.md`.
- HAPP conformance draft: `conformance-v0.3.md`.

### 14.2 Informative

- Entra adapter draft: `adapters/entra-oidc-v0.1.md`.
