Here are **starting answers** you can use as WG “strawman positions” (deliberately practical, vendor‑neutral, and compatible with the **Agent Passport + Dynamic Trust Checkpoints** framing).  [oai_citation:0‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## 1) Minimum claim set that is useful without over-collecting

### Proposed answer
Define a **two-tier** minimum:

### **Tier 0 (Absolute minimum for interoperability)**
Enough to answer *“is this agent legitimate, sponsored, and authorized for this class of operation?”* without leaking business details.

**MUST**
- `type` / `vct` (credential type identifier)
- `iss` (issuer identifier)
- `agent.id` (stable agent identifier)
- `sponsor.id` + `sponsor.kind` (who is accountable)
- `authority.grants[].cap` (capability identifiers)
- `status` pointer (revocation/suspension handle) **or** short `exp` (ideally both)
- `exp`/`nbf` (time validity) *or* an explicit policy that status is always checked

**SHOULD**
- `authority.grants[].constraints[]` (when constraints exist; keep them simple and typed)
- `authority.delegation` (can_delegate, max_depth)

**MUST NOT (by default)**
- Human identity of an end-user
- Prompt/plan content
- Transaction payloads
- Device fingerprinting identifiers beyond what’s required for holder binding

### **Tier 1 (Still lightweight, but operationally useful)**
Add the minimum to make audit and incident response workable:

**SHOULD**
- `agent.version` (build provenance for “which code did this?”)
- `agent.instance` (if you need instance-level revocation)
- `policy_ref` / `issuance_context` (pointer to issuance policy or assurance class)
- Optional: `delegation.parent` and/or a compact chain hint (hash list)

### Why this works
- Tier 0 is small enough for “IAM-light” orgs and individuals.
- Tier 1 is the minimum you’ll wish you had the first time there’s an incident.

**Privacy principle:** keep claims **about authority**, not **about data**.

---

## 2) Delegation chains represented and validated without heavyweight infrastructure

### Proposed answer
Start with a **“delegation by re-issuance”** model (simple, robust), and allow richer delegation later.

### **Baseline model (recommended for v1)**
- Delegation requires a **delegation authority** (issuer / sponsor / broker) to mint a **derived** credential or token for the downstream agent.
- The derived credential **MUST be a strict subset** (“monotonic narrowing”):
  - grants child ⊆ grants parent  
  - constraints child ≥ constraints parent (equal or stricter)
  - delegation depth ≤ configured max

### Minimal representation
**MUST**
- `delegation.parent` (reference to the parent authority artifact: credential ID / hash / `jti`)
- `delegation.delegated_by` (identifier of delegating agent or sponsor principal)
- `delegation.depth` (or derivable)

**SHOULD**
- `delegation.chain` as compact hints (e.g., hashes of each hop) for audit correlation

### Minimal validation rules at RP
- Verify each artifact signature and issuer trust (at least the leaf; for high risk, verify chain)
- Validate narrowing (subset checks)
- Enforce max depth
- Apply “ancestor revocation”: if a parent is revoked/suspended, derived credentials are invalid

### Why this is “lightweight”
- No need for distributed ledger, global graph resolution, or complex crypto attenuation on day one.
- Most complexity stays with issuers/brokers (who are best positioned to control delegation).

---

## 3) Which checkpoint evidence types are “baseline required,” versus optional profiles

### Proposed answer
Standardize **evidence categories + verification hooks**, and require only a small baseline that every ecosystem can realistically implement.

### **Baseline checkpoint evidence types (REQUIRED to support as categories)**
These are *abstract types*, not vendor tech choices:

1) **Elevated authentication** (step‑up identity)
   - “The actor has freshly re-authenticated at higher assurance”
   - Works with enterprise IdPs and IAM-light deployments
2) **Intent-bound human approval receipt**
   - “A human approved the exact Action Intent (WYSIWYS)”
   - Produces a verifiable artifact bound to an intent hash and time window
3) **Dual control / separation of duties**
   - “Two distinct approvals required” (role separation optional but recommended)
4) **Workload/device attestation (optional to require, but baseline to represent)**
   - “This agent/runtime/environment meets integrity requirements”
   - Even if not everyone uses it, the *type* should be representable

**Rationale:** these cover the majority of enterprise “rogue agent” mitigations while staying implementation-neutral.

### **Optional profiles (ecosystem-specific, pluggable)**
These are **profiles** a community can define without forcing adoption:

- **PoHP / deepfake-resistant liveness** (biometric or equivalent presence proof)
- Passkey/WebAuthn step-up profile
- Wallet-based proof profile
- Regulated industry profiles (payments, healthcare, etc.)

The WG can publish these as “profiles” under the Dynamic Trust Checkpoints umbrella so the core stays stable and vendor-neutral.  [oai_citation:1‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## 4) Minimal audit fields for enterprise investigations while preserving privacy

### Proposed answer
Define **two audit tiers**: a “privacy-minimal default” and an “elevated audit” for high-risk actions.

### **Tier A: Privacy-minimal default (MUST)**
Log only what you need to prove **who/what/when/why** without storing payloads.

**MUST**
- `event_id`
- `timestamp`
- `rp_id` / `system_id` (who executed)
- `operation_id` (what operation type)
- `outcome` (ALLOW/DENY)
- `reason_code` (policy_denied, constraint_failed, missing_capability, replay, etc.)
- `agent_id`
- `sponsor_id`
- `capability_id` evaluated
- `intent_hash` (hash of canonical Action Intent; avoids logging full payload)
- `evidence_refs` (IDs/hashes of checkpoint artifacts used)
- `artifact_refs` (hash of passport/permit token used; don’t store raw tokens in logs)

**SHOULD**
- `delegation_ref` (parent id/hash, depth) when delegation is in play
- `policy_version` (which ruleset made the decision)
- `correlation_id` (trace ID to link across systems)

### **Tier B: High-risk audit (SHOULD, triggered by policy)**
Add just enough to support fraud/finance/security investigations without copying sensitive data:

**SHOULD**
- `resource_ref` pointers (invoice ID / vendor ID) as **references**, not full payloads
- a minimal “display summary” (optional) that is generated deterministically from intent and redacts sensitive fields
- checkpoint assurance metadata (e.g., “step-up level met”, “two approvals present”) without leaking biometrics or raw identity attributes

### Privacy guardrails (normative posture)
- Prefer **hashes + references** over payload logging.
- Make logs configurable by **risk level** and retention policy.
- Protect audit access with least privilege and strong governance.

---

### One sentence to frame these in the WG
“Let’s standardize the smallest set of claims and evidence types that allow an RP to enforce capability constraints and dynamic trust checkpoints, while keeping audit records privacy-minimal and verifiable.”  [oai_citation:2‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)
