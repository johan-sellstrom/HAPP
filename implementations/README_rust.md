Here you go — a complete Rust reference implementation repo for **AAIF HAPP v0.3.4** (workspace + provider + RP verifier + conformance runner):

[Download the full Rust repository (v0.3.4)](sandbox:/mnt/data/aaif-happ-rs-v0.3.4.zip?_chatgptios_conversationID=695d202a-2480-832f-b2da-909fa747e136&_chatgptios_messageID=98ddedd3-c5e6-405d-8b2c-b18ea2159272)

## What’s included

- **`happ-core`**  
  Types + deterministic canonicalization + `intent_hash` + Signing View + `presentation_hash`.

- **`happ-crypto`**  
  JWT/JWS helpers (RS256 + HS256) with encode + decode-only modes.

- **`happ-provider`**  
  Provider state machine + **MCP stdio tool** (`aaif.happ.request`) + **provider-controlled web consent UI**.  
  Includes identity adapter interface +:
  - **Entra OIDC PKCE adapter** (`entra_oidc`) (real network OIDC flow, with practical validation)
  - **Entra mock adapter** (registered under the same scheme name `entra_oidc` by default, so offline/dev works)

- **`happ-rp`**  
  Relying Party verifier library: verifies signature, expiry, audience binding, `intent_hash`, `presentation_hash`, PoHP policy, replay protection, and embedded identity evidence (if required).

- **`happd`** (binary)  
  Runs **web UI + MCP stdio server** together.

- **`happ-conformance`** (binary)  
  Runs vector-based checks and writes a markdown summary.

## Quick start

```bash
unzip aaif-happ-rs-v0.3.4.zip
cd aaif-happ-rs-v0.3.4

cargo build --release

cargo run -p happd -- \
  --web-addr 127.0.0.1:8787 \
  --issuer did:web:provider.example \
  --signing-alg RS256 \
  --signing-key examples/keys/provider_rsa_private.pem \
  --public-key examples/keys/provider_rsa_public.pem \
  --identity-adapter entra_oidc
```

- Web consent UI: `http://127.0.0.1:8787/`
- MCP tool is served over **stdio** (connect using your MCP host/inspector)

### Conformance vectors

```bash
cargo run -p happ-conformance -- \
  --vectors test_vectors/v0.3 \
  --out conformance_summary.md
```

## Notes you should be aware of

- This ZIP was generated in an environment **without a Rust toolchain**, so I could not compile/test it here. The repo is written to compile on a normal Rust toolchain with `cargo` and dependency access.
- The Entra OIDC flow is implemented in a pragmatic way, but real-world Entra issuer/tenant patterns can be subtle (multi-tenant vs single-tenant). The code handles the common cases and enforces tenant allow-lists via policy where applicable.
- The included RSA keys under `examples/keys/` are **dev-only**.

If you want, I can also generate a companion **“RP demo binary”** (CLI that consumes an Action Intent + consent credential and prints a verification decision + reasons) in the same workspace.
