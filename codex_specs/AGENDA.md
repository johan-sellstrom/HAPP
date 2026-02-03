## WG agenda blurb (3–5 sentences)
As agents begin to execute real operations across systems, we need interoperable answers to: **who an agent acts on behalf of, what authority it has, and how that authority changes under risk**. This agenda item proposes a standards workstream for **Agent Passport (portable agent identity + delegated capabilities)** and **Dynamic Trust Checkpoints** that let relying parties require step‑up evidence (including explicit human approval when needed) for high‑risk actions. The goal is vendor‑neutral, testable profiles that work across agent runtimes, gateways, and enterprise workflows, with clear audit artifacts and revocation expectations.  [oai_citation:0‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## One-page proposal overview (vendor-neutral)

### Title
**Agent Passport + Dynamic Trust Checkpoints for Accountable Agent Actions**

### Problem
Identity systems were built for **humans logging into apps** and **apps calling APIs**, not for autonomous agents that plan, delegate, and transact across domains. As a result, systems struggle to reliably answer: **“Who does this agent act on behalf of, and what is it allowed to do?”** and to prove, after the fact, that high‑risk actions were appropriately authorized.  [oai_citation:1‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

### Objectives
1) Enable any relying party to verify **agent legitimacy, sponsorship/accountability, and delegated authority**.  
2) Enable **contextual step‑up** at the moment of risk (Dynamic Trust Checkpoints) without breaking low‑risk automation.  
3) Produce **audit-ready evidence** that is tamper-evident, privacy-minimal, and portable across systems.  
4) Support adoption by both **enterprise IAM** environments and **IAM-light** environments (small orgs / individuals).

### Scope (what we standardize)
**A) Agent Passport (portable identity + authority)**
- A minimal claim model for an agent credential that expresses:
  - agent identifier + provenance basics  
  - sponsor/accountable principal  
  - delegated capabilities + constraints  
  - delegation hooks (optional)  
  - revocation/status expectations  

**B) Dynamic Trust Checkpoints (contextual step-up)**
- A standard way for executors to say: “this action is higher risk—additional evidence is required.”
- Includes:
  - a machine-readable **Action Intent** representation (what will be executed)  
  - challenge/response patterns (how a relying party signals “insufficient authorization”)  
  - evidence categories (e.g., step-up, dual control, explicit human approval), without mandating a single vendor or method  
  - anti-replay rules (TTL, audience binding, one-time use)  
  - audit event guidance (minimum fields, privacy constraints)

### Non-goals (explicit)
- Not choosing a single identity provider, wallet, biometric method, or governance vendor.  
- Not mandating one deployment topology (runtime vs gateway vs workflow).  
- Not requiring disclosure of sensitive prompts or private reasoning traces to achieve auditability.

### How it works in practice (simple mental model)
1) **Prove baseline authority:** the agent presents an Agent Passport (or equivalent) so the relying party can evaluate delegated capabilities and constraints.  
2) **Gate high risk dynamically:** if risk triggers (amount thresholds, new vendor bank details, privileged access, external export), the relying party issues a **Checkpoint challenge** requiring additional proof.  
3) **Execute with durable evidence:** once satisfied, the relying party issues/accepts a **bounded authorization artifact** (short-lived, optionally single-use) tied to the Action Intent, and records an audit event.

### Deliverables (initial)
1) **Agent Passport claim profile** (minimal) + JSON schema  
2) **Dynamic Trust Checkpoints profile** (Action Intent + challenge/response + evidence categories)  
3) **Conformance tests** (what verifiers/enforcers must validate; negative tests)  
4) **Reference implementations** (verifier/enforcer at an API boundary; optional runtime integration stubs)  
5) **Privacy guidance** (data minimization, selective disclosure where possible, retention defaults)

### Success criteria
- Two independent implementations interoperate end-to-end in a demo scenario (e.g., payment approval / vendor bank change) with:  
  - capability evaluation + constraint enforcement  
  - checkpoint triggering and satisfaction  
  - replay protection  
  - audit artifact attachment to the transaction record  
- Clear “MUST/SHOULD” conformance criteria that reduce ambiguity for adopters.

### Open questions for the WG
- What is the minimum claim set that is useful without being over-collecting?  
- How should delegation chains be represented and validated without heavyweight infrastructure?  
- Which checkpoint evidence types should be “baseline required to support,” versus optional profiles?  
- What are the minimal audit fields that satisfy enterprise investigations while preserving privacy?

If you want, I can also give you a **1-paragraph “chair intro”** you can read aloud when the agenda item comes up, and a **2–3 bullet “ask”** for the WG (“approve workstream, nominate editors, agree first use cases”).
