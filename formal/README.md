# happ_proof

Lean 4 formal model and proofs for core HAPP safety invariants.

## Layout

- `HappProof/Protocol.lean`
  - Protocol state and transition model (`verifyAndConsume`).
  - Session/route bindings, challenges, replay flags, capability-checkpoint policy checks.
- `HappProof/Proofs.lean`
  - Machine-checked safety theorems over the model.
- `HappProof/E2E.lean`
  - End-to-end lifecycle model (`createSession`, `markPoHP`, `markIdentity`, `approve`, `deny`, `issueChallenge`, `execute`).
  - Global invariant definition and transition-preservation proof.
  - Credential-issuance correctness theorems and challenge atomic-consumption theorem.

## Proven Invariants (current)

- Route/session isolation:
  - `verify_rejects_route_mismatch`
- Approval-token non-replay guard:
  - `verify_rejects_used_jti`
- Capability/checkpoint pairing enforcement:
  - `verify_rejects_checkpoint_pairing`
- Challenge non-replay guard:
  - `verify_rejects_used_challenge`
- Successful non-challenge path consumes `jti`:
  - `verify_nonchallenge_path_marks_jti`
- Successful challenge path atomically consumes both `jti` and `challengeId`:
  - `verify_challenge_path_is_atomic`

## E2E Guarantees (current)

- Initial state satisfies global invariants:
  - `invariant_empty`
- Every modeled transition preserves invariants:
  - `step_preserves_invariant`
- Credential issuance succeeds in the approved/satisfied cases with expected claims:
  - `issueCredential_success_nonchallenge`
  - `issueCredential_success_challenge`
- Challenge execution update atomically marks token + challenge as consumed and clears outstanding challenge binding:
  - `executeWithChallenge_atomic_consumption`

## Build

```bash
cd formal
lake build
```

## Run demo executable

```bash
cd formal
lake exe happ_proof
```
