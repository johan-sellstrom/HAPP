# Proposal: HAPP — Human Authorization & Presence Protocol (AAIF)

## The problem
Agentic systems are moving from “assist” to “act” — executing tool calls that can move money, change permissions, delete data, export sensitive information, or trigger account recovery.

Today, most “human approval” is an in-product UI prompt:
- not portable across systems,
- hard to audit,
- vulnerable to replay,
- and increasingly exposed to spoofing and synthetic media.

MCP enables tool interoperability, but it intentionally does not enforce human consent and authorization at the protocol level.

## The proposal
**HAPP (Human Authorization & Presence Protocol)** is an AAIF standard that adds an interoperable “human authority” layer on top of MCP and/or HTTP APIs.

HAPP standardizes:
1. **Action Intent** — a deterministic, machine-readable intent (JSON DSL) describing the exact operation to authorize.
2. **WYSIWYS binding** — a **presentation hash** of the deterministic “Signing View” (what the human was shown) to prevent UI/intent mismatch.
3. **Consent Credential** — a portable, signed credential (VC/JWS) binding:
   - `intent_hash` (what will execute)
   - `presentation_hash` (what was shown)
   - `aud` (the relying party)
   - timestamps, replay controls, PoHP assurance level
   - provider certification evidence
4. **Proof of Human Presence (PoHP)** — vendor-neutral assurance levels (AAIF-PoHP-1..4) that let relying parties set policy based on risk.
5. **Optional Identity Binding** — pluggable adapters (schemes) so relying parties can choose:
   - PoHP-only (“a live human approved”), or
   - PoHP + enterprise identity (“this Entra user approved”).
6. **Relying Party Challenge Mode** — an RP can enforce HAPP at its API boundary (independent of whether MCP hosts mandate it).

## Why AAIF
AAIF is the neutral venue to standardize interoperable agent infrastructure and the trust layers that make it safe to deploy.

HAPP complements MCP and AGENTS.md by standardizing a missing layer: provable human authorization for sensitive actions.

## Why this can be successful
- **Relying Party driven:** RPs can require HAPP on sensitive endpoints. Agents that don’t comply simply can’t perform the action.
- **Integrate once / accept many:** RPs verify one credential format and accept proofs from any certified provider.
- **Vendor-neutral market:** multiple biometric and identity vendors can implement HAPP; the security floor is enforced by certification + conformance tests.
- **Practical now:** HAPP can be implemented today using MCP Tools + URL-mode user interaction for sensitive flows.

## Deliverables for incubation
- HAPP specification + schemas
- MCP profile for `aaif.happ.request`
- Conformance requirements + interop test harness
- Reference implementations:
  - Presence Provider (MCP + URL consent UI)
  - Relying Party verifier library
- Initial identity adapter: **Microsoft Entra OIDC**

## Ask from AAIF Steering
- Approve incubation as an AAIF standardization effort
- Establish governance for a provider certification registry (AAIF-run or delegated)
- Sponsor early interop events / plugfests
