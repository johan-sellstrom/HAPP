A clean way to get HAPP covered is to **treat it as a problem space + workstream** inside the WG’s existing “Agent Passport + Dynamic Trust + Auditability” mission—**not** as “our spec.” Your own WG briefing already sets you up for this because it explicitly calls for **dynamic, contextual trust checkpoints** and stronger **auditability/accountability** beyond static permissions.  [oai_citation:0‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

Below is a practical playbook that keeps it on-agenda while staying vendor‑neutral and non‑self‑promotional.

---

## 1) Put it on the agenda as a neutral workstream name
Use a name like:

**“High-Assurance Human Authorization for Agent Actions (HA-HAA)”**  
or  
**“Dynamic Trust Checkpoints for High-Risk Actions”**

Then describe HAPP as **one candidate approach**, not the centerpiece.

**Neutral problem statement (copy/paste):**  
> “When agents execute high-risk actions (payments, vendor bank changes, privileged access), what evidence should a relying party require to prove a human approved the *exact* action, and how should that evidence be verifiable and auditable across domains?”

This aligns directly with the WG’s stated “dynamic trust” and “auditability/accountability” gaps.  [oai_citation:1‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## 2) Sequence the work so the WG “earns” the solution
Avoid “here’s HAPP.” Instead do:

### Phase A — Requirements first (2–3 meetings)
Deliverable: **Requirements + threat model** for “human approval evidence” in agent workflows.
- Presence vs identity
- UI mismatch (“show X, sign Y”)
- replay/token hoarding
- deepfake resistance
- dual control / SoD
- privacy-minimal audit logs
- cross-domain verification

### Phase B — Candidate approaches (1–2 meetings)
Create a “patterns catalog” with multiple options:
- step-up via IdP/Conditional Access / claims challenge
- hardware-backed approvals (passkeys/WebAuthn)
- wallet-based verifiable presentations
- biometric PoHP approaches
- signed “consent receipts” bound to intent

### Phase C — Interop profile + conformance (later)
Only after A & B do you propose the “HAPP-shaped” artifact as a profile that meets the requirements.

This makes it clear you’re *not* pushing a pre-baked product; you’re proposing a standards process.

---

## 3) Frame it as a missing “dynamic trust primitive”
In the WG briefing, “dynamic trust” is about **adjusting trust/permission based on risk at task time**, plus continuous validation.  [oai_citation:2‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)  
So position the workstream as:

- **Agent Passport** = static-ish baseline: who/what the agent is, provenance, authority scope
- **Dynamic Trust Checkpoint** = per-action gate: when risk spikes, require stronger evidence
- **Auditability** = portable evidence of “who approved what, when, and under what assurance”

That storyline makes the “human approval evidence” workstream feel inevitable.

---

## 4) Add a short charter bullet that guarantees coverage
Drop this into the WG charter “Key Scope Areas” section (vendor-neutral wording):

> **Dynamic Trust Checkpoints:** Define interoperable mechanisms for step-up authorization of high-risk agent actions, including standardized representations of action intent, human approval evidence, anti-replay controls, and audit metadata. The WG will evaluate multiple approaches and publish conformance criteria.

No mention of HAPP required—but it ensures the topic is in scope.

---

## 5) Put “HAPP” on the agenda as a case study, not a headline
Agenda item wording that doesn’t sound self-serving:

**“Case study: high-risk financial actions (payment release / vendor bank change)”**  
- What evidence is needed?
- What must be shown to a human?
- Where is enforcement?
- How do we audit?

Then (near the end) you can say:
> “We have a strawman design we can share that tries to satisfy these requirements—happy to contribute it as an input.”

That keeps the room in “requirements” mode.

---

## 6) Make it obviously not vendor lock-in
Three small moves make a huge difference in perception:

1) **Explicitly invite alternatives**  
“Bring your preferred method: passkeys, wallets, IdP step-up, biometrics, etc.”

2) **Define conformance tests before picking winners**  
“Any vendor can implement if they pass the tests.”

3) **Offer iProov as *one implementer***  
“We’ll contribute a reference implementation and participate in interop—others welcome.”

---

## 7) A 20-second chair script (non-salesy)
> “The WG is tackling Agent Passport and dynamic trust. A recurring gap is high-risk actions where static permissions aren’t enough—payments, bank changes, privileged access. We should define what a ‘dynamic trust checkpoint’ looks like: what intent is being approved, what evidence is acceptable, how replay/UI-mismatch/deepfakes are handled, and how it’s audited across domains.”

---

## 8) Concrete agenda plan for the first 3 sessions
1) **Session 1 — Use cases + threat model**  
Output: top 5 must-gate actions and failure modes

2) **Session 2 — Requirements checklist**  
Output: “MUST/SHOULD” list for trustworthy human approval evidence

3) **Session 3 — Compare patterns**  
Output: mapping of approaches to requirements; identify gaps

Only after that: propose an interop profile.

---

### Bottom line
You “get HAPP covered” by **embedding it as a necessary sub-problem of dynamic trust and auditability**, then letting the WG converge on requirements and only later introducing HAPP as a strawman that meets them. That reads as leadership, not self-promotion.
