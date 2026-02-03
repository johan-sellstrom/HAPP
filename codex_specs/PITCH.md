Here’s the high-level summary of the standards proposal you’re developing.

## What we’re proposing
A vendor-neutral standards suite (under [AAIF](chatgpt://generic-entity?number=0)) that makes **autonomous agent actions safe, auditable, and interoperable** across ecosystems by standardizing two things:

1) **Agent identity + delegated authority** (“Who is this agent acting for, and what baseline capabilities has it been delegated?”)  
2) **Dynamic Trust Checkpoints** for high‑risk actions (“This specific action is risky—what additional proof is required *right now* before execution?”)

This is motivated by the fact that classic identity systems were designed for humans and app-to-app calls, not autonomous agents that delegate, transact, and operate across domains.  [oai_citation:0‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## The core building blocks

### 1) Agent Passport (portable agent identity + authority)
A portable “Agent Passport” credential that an agent can present to a relying party to prove, in a verifiable way:
- **Provenance**: who issued/built the agent
- **Sponsorship/accountability**: which org/principal stands behind it
- **Delegated authority**: what capabilities it is allowed to exercise
- **Constraints**: limits such as amount thresholds, allowlists, time windows, delegation limits
- **Revocation expectations**: how the relying party can check “still valid” at decision time

The intent is that this can be compatible with VC/OID4VC-style patterns and still be usable in “IAM-light” environments (small orgs, individuals) where a full enterprise IAM deployment isn’t available.  [oai_citation:1‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

### 2) Dynamic Trust Checkpoints (contextual step‑up at the moment of risk)
A standard checkpoint model that lets the executor (RP, gateway, tool server, workflow engine) say:
- “This request is higher risk than normal—**present additional evidence** before I execute it.”

Key pieces:
- **Risk triggers** (policy-driven): amount thresholds, new beneficiary, vendor bank change, privilege grant, large export, etc.
- **Action Intent**: a machine-readable description of *what will be executed* (so approval/proof binds to exact semantics)
- **Challenge/response semantics**: how the RP signals “insufficient authorization” and how agents respond with evidence
- **Evidence artifacts**: what “proof” looks like, how it is verified, and how it is logged
- **Anti-replay**: TTL, audience binding, one-time use, replay caches
- **Audit hooks**: durable, minimally invasive records suitable for SIEM and investigations

This is the standards home for “human-in-the-loop” requirements without hardwiring a single vendor or a single method.  [oai_citation:2‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

### 3) HAPP as a checkpoint profile (high-assurance human approval)
Within Dynamic Trust Checkpoints, HAPP is the profile for “a human must approve” with:
- **Proof of Human Presence (PoHP)** levels (deepfake-resistant liveness as a requirement where needed)
- Optional **enterprise identity binding** (e.g., an approver identity), but separable from presence
- **WYSIWYS** binding (what was shown vs what was signed/executed)
- A portable **Consent Credential/receipt** that an RP can verify and attach to the transaction record

HAPP is vendor-neutral by design:
- multiple certified PoHP providers can implement it (e.g., [iProov](chatgpt://generic-entity?number=1) as one implementer)
- RPs decide whether they require **presence only** or **presence + identity** based on policy

---

## How it fits with MCP without “changing everything”
This suite is designed to sit **on top of MCP** as an interoperability layer:
- MCP remains the tool invocation interface.
- The extensions define how tools/actions declare **required capability scopes** and/or **checkpoint requirements**.
- Enforcement is done where it matters: **the relying party / gateway / tool server** (not the UI).

---

## Enforcement and audit model (the “so what?”)
- **Relying parties enforce**: they verify the Agent Passport (or derived tokens) and require/checkpoint evidence for high-risk operations.  [oai_citation:3‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)  
- **Auditors get durable artifacts**: proofs are attached to the executed action (payment, bank change, access grant, export) with replay resistance and clear “chain of command” metadata.  [oai_citation:4‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)  
- **Privacy is preserved by default**: minimal disclosure, optional identity binding, selective disclosure where possible, short-lived proofs, and configurable logging.

---

## Why this could succeed
- It addresses the *missing primitives* everyone is now running into: agent accountability, delegation, cross-domain trust, and high-risk action control.  [oai_citation:5‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)  
- It’s **vendor-neutral** and additive: it doesn’t require replacing existing IAM; it complements it and works in “IAM-light” environments.  
- It creates a clear ecosystem path: open conformance profiles, testable requirements, and multiple implementations (including strong PoHP providers) rather than a single proprietary control plane.

