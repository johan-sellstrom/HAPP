# AAIF HAPP (Rust) — Reference Implementation (v0.3.4)

This repository is a **Rust reference implementation** of the **AAIF HAPP** specification (Human Authorization & Presence Protocol) at **v0.3.4**.

It implements:

- **Action Intent** canonicalization + `intent_hash`
- **Signing View** derivation + `presentation_hash` (WYSIWYS)
- **HAPP Challenge mode** (RP-enforced) and **MCP tool mode**
- **Consent Credential** issuance (JWS/JWT) and verification
- **Identity binding** as a pluggable adapter system:
  - `entra_oidc` adapter (Authorization Code + PKCE) **skeleton**
  - `entra_mock` adapter for offline development and conformance runs
- **MCP stdio server** exposing `aaif.happ.request`
- **Provider-controlled URL UI** for the human consent step
- **Conformance harness** with requirement-id oriented checks and vectors

> **Note:** This environment (where this ZIP was generated) does not contain a Rust toolchain,
> so this code was not compiled here. It is written to compile on a standard Rust 1.74+ toolchain
> with `cargo` and internet access to fetch dependencies.

---

## Workspace layout

- `crates/happ-core` — types, canonicalization, hashing, signing view
- `crates/happ-crypto` — JWT/JWS encode/decode helpers
- `crates/happ-provider` — provider state machine, identity adapters, credential issuance
- `crates/happ-rp` — relying-party verifier library (policy checks + replay mitigation)
- `crates/happd` — runnable server: MCP stdio + URL UI in one process
- `crates/happ-conformance` — conformance runner (vectors + checks)

---

## Quick start

### 1) Build

```bash
cargo build --release
```

### 2) Run the reference provider (MCP stdio + web UI)

```bash
cargo run -p happd -- \
  --web-addr 127.0.0.1:8787 \
  --issuer did:web:provider.example \
  --audience did:web:rp.example \
  --signing-key examples/keys/provider_rsa_private.pem \
  --signing-alg RS256 \
  --identity-adapter entra_mock
```

Then open:

- Consent UI: http://127.0.0.1:8787/
- MCP is served over **stdio** (connect using your MCP host/inspector).

### 3) Run conformance checks

```bash
cargo run -p happ-conformance -- \
  --vectors test_vectors/v0.3 \
  --out conformance_summary.md
```

---

## Entra adapter (enterprise identity binding)

The `entra_oidc` adapter is included as a **realistic skeleton**:
- Authorization Code + PKCE
- nonce/state binding
- ID token validation (when enabled)

To use it, you must register an Entra app and configure:

- client id
- client secret (if required)
- redirect URL (must match what the server is listening on)
- allowed tenant(s)

See `crates/happ-provider/src/adapters/entra_oidc_pkce.rs`.

---

## Disclaimer

This is a reference implementation to accelerate interop. Do not treat it as production-ready.
Hardening items for production include:
- secure key storage and rotation
- persistent replay cache
- robust anti-CSRF protections for the consent UI
- hardened DID/JWKS resolution and certification registry checks
- full PoHP integration (biometrics/liveness) with certified providers


## Entra claims challenge transport

The `entra_oidc` adapter can now carry an optional Entra `claims` request on the authorization redirect. This lets enterprise deployments reuse Entra claims-challenge / auth-context policies while still issuing a normal HAPP Consent Credential at the end of the flow.
