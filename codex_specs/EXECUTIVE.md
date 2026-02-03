## Executive summary: HAPP (Human Authorization & Presence Protocol)

### What HAPP is
**HAPP** is a proposed **open, vendor‑neutral standard** that lets AI agents and automated systems obtain **cryptographically verifiable human approval** for high‑risk actions—such as **payment release** and **vendor bank account changes**—and present that proof to a **Relying Party** (the system executing the action).

HAPP sits **on top of MCP** (as an MCP tool/profile) and also works without MCP via an **API-boundary challenge pattern**. It standardizes the *artifacts and verification rules* for approvals, not the biometric algorithms themselves.

### The problem it solves
Today, “human-in-the-loop” approvals are typically:
- UI-only prompts with no portable proof
- hard to audit
- vulnerable to replay and token reuse
- increasingly vulnerable to deepfakes and injection attacks
- inconsistent across agent frameworks and enterprise platforms

As agentic AI moves from “assist” to “act,” enterprises need a way for systems to answer, reliably and auditably:

**“Which human approved this exact action, right now?”**

### The core idea
HAPP introduces three interoperable building blocks:

1) **Action Intent (machine-readable)**
A deterministic JSON DSL describing *exactly what will be executed* (who/what/where/how much), plus constraints (expiry, one-time use, limits).  
The Action Intent is canonicalized and hashed (`intent_hash`) to prevent tampering.

2) **Proof of Human Presence (PoHP)**
A high-assurance verification event that a **real, live human** was present and explicitly approved the action—designed to be **deepfake‑resistant**.  
PoHP is represented as a small set of **assurance levels** (e.g., PoHP‑1…PoHP‑4) so relying parties can set policies like “PoHP‑4 required for vendor bank changes.”

3) **Consent Credential (verifiable and auditable)**
A signed credential (VC/JWS) issued by a certified Presence Provider that binds:
- the `intent_hash` (what was approved)
- the `audience` (where it can be used)
- timestamps (freshness/expiry)
- a unique ID (`jti`) for replay prevention
- PoHP assurance (level, method, verifiedAt)
- optional identity binding (who approved)

It also includes a **`presentation_hash`** (hash of the deterministic “Signing View”) to enforce **WYSIWYS** (“what you see is what you sign”) and stop bait‑and‑switch UI attacks.

### Presence vs identity (policy-driven)
HAPP cleanly separates:
- **Presence**: “a real human approved”
- **Identity**: “which human (enterprise user) approved”

A relying party decides per endpoint whether:
- liveness alone is enough, or
- liveness + identity binding is required

For enterprise, HAPP supports **pluggable identity adapters**, starting with **Microsoft Entra ID** (tenant+user object ID binding), so approvals can be tied to enterprise roles and separation-of-duties controls.

### How it fits enterprise architecture
HAPP is designed to be enforced where enterprises want control:

- **At the API boundary (e.g., APIM)**: “No credential, no execute.”  
  This enables adoption even if every agent platform isn’t updated yet.
- **In agent tooling (MCP)**: as a standard tool (`aaif.happ.request`) that triggers an out‑of‑band approval UI.
- **In workflows (ERP/IAM)**: as an auditable approval artifact attached to existing approval steps.

### Multi-vendor, certified ecosystem
HAPP is intentionally **open to all certified vendors**. It avoids lock‑in by:
- standardizing outputs and verification rules,
- defining conformance tests and assurance levels,
- using certification credentials and registries so relying parties can verify providers without custom integrations.

Vendors compete on:
- liveness/deepfake resistance,
- UX,
- cost,
- compliance,
- reliability

—while relying parties integrate once.

### Why it’s likely to succeed
HAPP is positioned to be adoptable because it:
- addresses an urgent, shared gap in agentic AI security (verifiable human approval)
- is implementable immediately using existing patterns (MCP tools + URL flow, or RP challenge enforcement)
- improves auditability and reduces fraud risk in high-value workflows
- is vendor-neutral and certification-based, aligning with open standards governance
- maps cleanly to enterprise identity and control planes (e.g., Entra, APIM, ERP approvals)

### The intended outcome
A world where enterprises can safely allow agents to take action because every sensitive action can carry a **portable, verifiable proof** answering:

- **What was approved?** (`intent_hash`, `presentation_hash`)  
- **Who approved it?** (optional identity binding)  
- **When, and how strong was the proof?** (PoHP level + timestamps)  
- **Is this provider trustworthy?** (certification evidence)  

HAPP turns “human-in-the-loop” from an interface convention into a **verifiable security control**.
