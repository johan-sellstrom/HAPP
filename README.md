# AAIF HAPP v0.3.4 (Draft)

This repository contains the draft AAIF HAPP specification plus reference code for local interoperability testing.

HAPP (Human Authorization and Presence Protocol) standardizes how an agent obtains explicit human approval for a machine-readable action intent and receives a portable consent credential that a relying party can verify.

## Scope and terminology

- The credential format in this repo/spec is **HAPP-CC** (HAPP Consent Credential).
- Some external notes use the term **JWC**; in this repository, the standards term is HAPP-CC.
- The MCP profile in v0.3.4 currently defines **one** tool: `aaif.happ.request`.
- This is a **reference** implementation for flow validation and conformance work, not a production service.

## What is included

- Draft spec and schemas for:
  - Action Intent (AI-INTENT)
  - Relying Party Challenge (HAPP-CHAL)
  - Consent Credential (HAPP-CC)
  - Provider Certification Credential (HAPP-PCC)
- MCP profile for URL-mode consent flow (`aaif.happ.request`)
- Python reference implementation (`implementations/python/`) with:
  - MCP stdio server
  - Local consent UI (`http://127.0.0.1:8787`)
  - Optional Entra identity binding (mock mode + real PKCE flow skeleton)
  - RP-side credential verifier helper
- Interop harness (`interop/`) that runs the bundled conformance tests
- Rust reference workspace (`implementations/rust/`)

## Implemented MCP flow (Python reference)

1. MCP host calls `aaif.happ.request` with `actionIntent` (or `challenge`).
2. Provider returns JSON-RPC error `-32042` with URL elicitation data.
3. Human opens provider UI, reviews intent, optionally completes identity binding, then approves or denies.
4. Host retries the same tool call.
5. Provider returns `structuredContent` with a HAPP-CC envelope.

## Quick start (Python demo)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r implementations/python/requirements.txt
```

Start MCP server + consent UI:

```bash
python implementations/python/bin/run_happ_mcp_server.py
```

In another terminal, run the local end-to-end tool-call simulation:

```bash
python implementations/python/examples/demo_mcp_flow.py
```

For identity-required flow:

```bash
python implementations/python/examples/demo_mcp_flow.py --require-identity
```

## Entra identity binding modes

### 1) Mock mode (default, offline)

- UI shows "Use mock Entra identity (offline)".
- Generates an RS256-signed Entra-like ID token and embeds evidence in `identityBinding`.

Optional mock subject overrides:

```bash
export HAPP_ENTRA_MOCK_TID=00000000-0000-0000-0000-000000000000
export HAPP_ENTRA_MOCK_OID=11111111-1111-1111-1111-111111111111
```

### 2) Real mode (Authorization Code + PKCE skeleton)

```bash
export HAPP_ENTRA_MODE=real
export HAPP_ENTRA_TENANT_ID=common
export HAPP_ENTRA_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export HAPP_ENTRA_REDIRECT_URI=http://127.0.0.1:8787/entra/callback
export HAPP_ENTRA_SCOPE="openid profile email"
```

In real mode, the UI shows "Sign in with Entra" and performs an OIDC Authorization Code + PKCE redirect flow.

## Conformance harness

Run bundled conformance tests:

```bash
python interop/run_conformance.py
```

Run against the reference HTTP provider:

```bash
python implementations/python/bin/run_ref_provider_http.py --port 8766
python interop/run_conformance.py --sut http://127.0.0.1:8766
```

## Important current limitations

- Provider-issued HAPP-CC in the Python demo uses `HS256` (`HAPP_DEMO_HS256_SECRET`) for simplicity.
- Intent hashing uses deterministic JSON encoding, not full RFC 8785 JCS.
- Session state is in-memory only (`implementations/python/happ/session_store.py`).
- Real Entra callback path does not perform full JWKS signature validation in the UI handler.
- No production controls for revocation lists, replay caches, key rotation, audit pipeline, PIM policy checks, or Graph notification routing are implemented in this reference demo.

## Specification map

- Core spec: `specification/draft/happ-v0.3.4.md`
- MCP profile: `specification/draft/mcp-profile-v0.3.4.md`
- Conformance: `specification/draft/conformance-v0.3.md`
- Entra adapter: `specification/draft/adapters/entra-oidc-v0.1.md`
- AI intent profile note: `specification/draft/ai-intent-profiles/ai-ui-confirm-v1.md`
- Schemas: `schemas/`

## Related docs

- `docs/one-pager-aaif-steering.md`
- `docs/agents-md-snippet.md`
- `docs/enterprise-entra-adapter.md`
