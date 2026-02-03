Here’s a **lightweight, MCP-native** way to express “what is this agent allowed to do?”—including **capabilities, constraints, delegation, and revocation**—without requiring every adopter to already have a full-blown IAM stack.

This aligns with your WG framing around “permission scope” + “dynamic trust” + “auditability.”  [oai_citation:0‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)

---

## Design goal
A minimal add‑on to MCP should:

1) **Reuse MCP’s existing authorization plumbing** (tokens at the transport level; step‑up when needed).  [oai_citation:1‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  
2) Let servers express **tool-level permission requirements** (not only “server-wide”). There’s already active discussion in MCP land about declaring tool-level scopes.  [oai_citation:2‡GitHub](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1880)  
3) Support **small orgs / individuals**: the MCP server itself (or a tiny sidecar) can mint capability tokens—no enterprise IdP required.  
4) Provide a policy language that’s:
   - **easy** for basic use cases (lists/limits)
   - **expressive** for advanced ones (conditions on parameters)
5) Handle **revocation** and (optionally) **delegation chains**.

---

## The lightweight protocol: “Tool-Level Capabilities + Capability Tokens”
Think of it as two pieces:

### Piece A — Tool-level requirements in `tools/list`
Extend tool metadata to declare what’s required to call each tool.

Why: MCP already has `tools/list`, and the spec explicitly anticipates human‑in‑the‑loop / safety UX even though it can’t enforce it by itself.  [oai_citation:3‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/server/tools)

**Proposal (fits MCP’s extension approach):**
Add an optional `authorization` object to each Tool entry—very similar to what’s being proposed in SEP‑1880 for tool-level scopes.  [oai_citation:4‡GitHub](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1880)

Example:
```json
{
  "name": "payments.release",
  "description": "Release a payment proposal / pay-run item",
  "inputSchema": { "type": "object", "properties": { "amount": {"type":"number"}, "vendorId": {"type":"string"} }, "required": ["amount","vendorId"] },
  "authorization": {
    "scopes": ["payments:release"],
    "capabilities": ["cap:mcp:tool/payments.release#call"],
    "constraints": [
      { "type": "max_amount", "value": 5000, "currency": "USD" },
      { "type": "vendor_allowlist", "values": ["V-001234", "V-004321"] }
    ],
    "policy": {
      "engine": "cel",
      "expr": "request.amount <= 5000 && request.vendorId in ['V-001234','V-004321']"
    }
  }
}
```

**Interpretation (server-side):**
- `scopes` / `capabilities` say *what class of authority* is required.
- `constraints` / `policy` say *how authority is limited* (limits, allowlists, etc.).

> Why include both `constraints` and `policy`?  
> Because you want a **low-bar** path that doesn’t require shipping a full expression engine, while still allowing advanced deployments.

---

### Piece B — A compact “Capability Token” presented with each call
MCP authorization is at the transport level for HTTP, and for STDIO transports the spec says to retrieve credentials from the environment.  [oai_citation:5‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  
So the token can be carried as:
- HTTP header(s) (for streamable HTTP transports)
- env var(s) for STDIO

**Lightweight token format:** a signed JWT/JWS (or similar) called a **Capability Token** that contains grants + constraints.

#### Minimal claim set (MVP)
```json
{
  "iss": "https://cap-issuer.example",
  "sub": "agent:1234",
  "aud": "https://mcp.example.com",
  "iat": 1730000000,
  "exp": 1730000600,
  "jti": "9b1deb4d-...",
  "grants": [
    {
      "cap": "cap:mcp:tool/payments.release#call",
      "where": { "engine": "cel", "expr": "request.amount <= 5000" }
    }
  ],
  "delegation": {
    "can_delegate": false
  }
}
```

**Enforcement rule:**  
When `tools/call` arrives, the server evaluates:
- Does the token include a grant for this tool?
- Do constraints pass for this specific request?

---

## “Permission denied” should reuse MCP’s existing step-up behavior
MCP already defines how to handle **insufficient scopes at runtime** using `HTTP 403` and `WWW-Authenticate: Bearer error="insufficient_scope" ... scope="..."`.  [oai_citation:6‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  
So your add-on should **not invent a new error scheme** unless necessary.

Recommended pattern:

1) If the agent lacks *coarse permission* → respond with `insufficient_scope` (telling it what to request).  [oai_citation:7‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  
2) If it has coarse permission but violates *constraints* → return a structured tool error such as:
   - `error_code: "policy_denied"`
   - `reason: "max_amount_exceeded"`
   - minimal debug info (avoid leaking sensitive allowlists)

This keeps the protocol lightweight and consistent with existing MCP auth handling.

---

## How this stays friendly to orgs without “advanced IAM”
You support **two issuance modes**, both compatible with the same verification rules:

### Mode 1 — Full IAM (enterprise)
- Tokens minted by an IdP / authorization server.
- Tool-level `scopes` map cleanly to OAuth consent and step-up flows.  [oai_citation:8‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  

### Mode 2 — “Embedded issuer” (small org / individual)
No IdP required. The MCP server (or a tiny sidecar) acts as a simple capability issuer:

- Admin creates a role/policy file locally:
```yaml
roles:
  ap_clerk:
    grants:
      - cap: "cap:mcp:tool/payments.release#call"
        constraints:
          - type: max_amount
            value: 5000
```

- A CLI or endpoint mints a signed token:
  - `mcpctl mint --role ap_clerk --agent agent:1234 --ttl 10m`
- The agent stores it as an env var or config secret.

This is materially better than API keys because it is:
- scoped
- time-bound
- auditable (via `jti`)
- revocable (see below)

And it matches MCP’s expectation that STDIO credentials come from the environment.  [oai_citation:9‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)

---

## Policy language: don’t bet the farm on a single DSL
A good “WG-friendly” move is to define **tiers**, so implementers can start small:

### Tier 0: Scope-only
- Tool requires `authorization.scopes`
- Server checks scope
- Done  
(SEP‑1880 is basically this direction.)  [oai_citation:10‡GitHub](https://github.com/modelcontextprotocol/modelcontextprotocol/issues/1880)

### Tier 1: Typed constraints (JSON)
Supports 80% of real-world needs without a full interpreter:
- `max_amount`
- `currency_allowlist`
- `vendor_allowlist / denylist`
- `time_window`
- `rate_limit`
- `one_time_use`

### Tier 2: Expression (CEL recommended)
For “constraints based on request parameters,” allow `policy.engine="cel"` and a restricted expression.
This has a practical adoption advantage: gateway projects already use CEL for access rules (so there’s precedent and libraries).  [oai_citation:11‡kgateway.dev](https://kgateway.dev/docs/agentgateway/main/rbac/?utm_source=chatgpt.com)

**Important security rule:** If a server doesn’t understand a policy engine or constraint type, it **MUST deny**, not ignore. (Otherwise policies become “decorations.”)

---

## Delegation chains (keep it simple in v0.1)
Delegation is important, but “agents re-signing authority” can get complicated fast.

**Lightweight v0.1 approach: “delegation by re-issuance”**
- Only the issuer can mint/attenuate tokens.
- Agent A asks issuer to mint a token for Agent B that is a subset.
- Token includes:
  - `delegated_by: agent:A`
  - `parent_jti: ...`
  - and a strict subset of grants/constraints

This gives you delegation chains **without requiring every agent runtime to implement complex attenuation crypto**.

---

## Revocation (make it work without an IdP)
You need revocation even for “small” setups.

Use layered defenses:

1) **Short TTL** (minutes for high-risk tools, hours for low-risk)  
2) **Replay detection** via `jti` cache (especially for one-time approvals)  
3) **Key rotation** (invalidate whole classes of tokens quickly)  
4) Optional: a simple `revocation_list` endpoint (or file) keyed by `jti`

MCP’s authorization model already expects strict audience binding and correct token handling; your extension should inherit that posture.  [oai_citation:12‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)

---

## How this differs from (and complements) Dynamic Trust Checkpoints
Capability tokens answer **“is the agent generally allowed to call this tool under these constraints?”**  
Dynamic trust checkpoints answer **“this specific invocation is unusually risky; what extra proof is required now?”** 

You can encode checkpoint requirements in tool metadata (e.g., “above $X requires step‑up”), but the key is: **capabilities ≠ per-action approval evidence**.

---

## A minimal “WG deliverable” shape
If you want this to be an AAIF/MCP add-on that people will actually implement, I’d define:

1) **Tool authorization metadata** (scopes + capabilities + optional constraints/policy)  
2) **Capability Token format** (JWT/JWS profile)  
3) **Evaluation semantics** (how servers decide allow/deny)  
4) **Error handling** (reuse `insufficient_scope` for coarse; structured deny for constraints)  [oai_citation:13‡modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/authorization)  
5) **Conformance levels** (Tier 0/1/2)  
6) **Reference implementations** (server + simple issuer CLI)

That’s enough to make “what is it allowed to do?” real—without forcing everyone to stand up enterprise IAM on day one.

If you want, I can draft  [oai_citation:14‡wg.md](sediment://file_00000000606071f4bbc168367cee2f9c)** for this (“MCP Capability Grants Extension”) with exact MUST/SHOULD language and a canonical JSON schema for:
- `Tool.authorization`
- `CapabilityToken.grants[]`
- `constraints[]` (Tier 1)
- `policy` (Tier 2, CEL subset)
