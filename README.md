# AAIF HAPP v0.3.4 (Draft)

**HAPP (Human Authorization & Presence Protocol)** is a proposed AAIF standard that adds **portable, verifiable human consent** (and optional **enterprise identity binding**) on top of agentic tool execution.

This v0.3.4 bundle includes:

- **Specification + schemas** for:
  - Action Intent (machine-readable intent DSL)
  - Relying Party Challenge (HAPP-CHAL)
  - Consent Credential (HAPP-CC) with:
    - `intent_hash` (what is executed)
    - `presentation_hash` (what was shown to the human, WYSIWYS)
    - optional `identityBinding` (pluggable, policy-driven)
  - Provider Certification Credential (HAPP-PCC)

- **Interop harness** (`interop/`) that can run conformance checks by requirement ID (policy-driven, adapter-aware).

- **Reference implementation** (`implementations/python/`) featuring:
  - A minimal **MCP stdio server** exposing `aaif.happ.request`
  - **URL-mode consent UI** (local web UI) that:
    - shows the intent summary
    - allows approval/deny
    - optionally requires **Entra identity binding**
  - A pluggable **Identity Binding adapter interface**
  - A starter **Microsoft Entra OIDC PKCE adapter skeleton**
  - A **mock Entra mode** for local/offline development (issues a signed RS256 “Entra-like” ID token)

> ⚠️ Security note: the reference implementation is for **end-to-end flow validation** and **interop/conformance** only. It is not production hardened.

---

## Quick start (local demo)

### 1) Create a venv and install deps
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r implementations/python/requirements.txt
```

### 2) Run the reference MCP Presence Provider + consent UI
This starts:
- MCP server over **stdio**
- Consent UI at http://127.0.0.1:8787

```bash
python implementations/python/bin/run_happ_mcp_server.py
```

### 3) Try a demo tool call (no MCP host required)
This simulates what a host would do:
- first call returns URL elicitation required + link
- you approve in the browser
- second call returns a HAPP Consent Credential

```bash
python implementations/python/examples/demo_mcp_flow.py
```

---

## Entra identity binding (enterprise)

HAPP supports identity binding as a **policy knob**:
- relying party may require **PoHP only**, or
- **PoHP + identity binding** (e.g., Entra user in tenant T)

In the demo implementation there are two modes:

### A) Mock Entra mode (default, offline)
The UI provides “Use mock Entra identity” to generate a signed RS256 ID token and satisfy `identity.mode=required`.

### B) Real Entra mode (PKCE skeleton)
The code includes a complete PKCE state machine and token-validation skeleton, but you must configure your own Entra app registration:

Environment variables (example):
```bash
export HAPP_ENTRA_MODE=real
export HAPP_ENTRA_TENANT_ID=common
export HAPP_ENTRA_CLIENT_ID=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
export HAPP_ENTRA_REDIRECT_URI=http://127.0.0.1:8787/entra/callback
```

Then the UI will show “Sign in with Entra” which starts the OIDC Authorization Code + PKCE flow.

---

## Interop conformance harness

Run conformance checks (vectors only):
```bash
python interop/run_conformance.py
```

Run conformance checks against the **reference HTTP SUT**:
```bash
python implementations/python/bin/run_ref_provider_http.py --port 8766
python interop/run_conformance.py --sut http://127.0.0.1:8766
```

---

## Where to look

- Spec: `specification/draft/happ-v0.3.4.md`
- MCP profile: `specification/draft/mcp-profile-v0.3.4.md`
- Conformance: `specification/draft/conformance-v0.3.md`
- Entra adapter: `specification/draft/adapters/entra-oidc-v0.1.md`
- Code: `implementations/python/happ/`


- Docs:
  - `docs/one-pager-aaif-steering.md`
  - `docs/agents-md-snippet.md`
  - `docs/enterprise-entra-adapter.md`
