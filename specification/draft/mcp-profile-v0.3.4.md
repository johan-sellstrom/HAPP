# HAPP over MCP v0.3.4 (Profile)

**Status:** Draft  
**Version:** 0.3.4  
**Tool namespace:** `aaif.happ.*`

## 1. Summary

This profile standardizes how a Presence Provider (PP) is exposed as an **MCP Server** that can issue HAPP Consent Credentials.

It uses:
- MCP `tools/list` for discovery
- MCP `tools/call` for invocation
- **URL-mode** consent UI for sensitive interactions (PoHP + identity binding)

## 2. Required capabilities

### Presence Provider MCP Server
- MUST implement MCP Tools.
- MUST expose tool `aaif.happ.request`.

### MCP Host/Client
- MUST support safe navigation to provider-controlled UI (URL-mode), including:
  - clear domain display
  - user consent before navigation

## 3. Tool: `aaif.happ.request`

### 3.1 Purpose
Request a HAPP Consent Credential (HAPP-CC) for an Action Intent (AI-INTENT), optionally driven by an RP Challenge (HAPP-CHAL).

### 3.2 Input arguments (logical model)

`aaif.happ.request` accepts either:

A) Agent-initiated:
- `actionIntent` (AI-INTENT)
- `requirements` (PoHP + optional identity binding)

B) RP Challenge Mode:
- `challenge` (HAPP-CHAL)

For high-risk actions, MCP Hosts/Clients SHOULD prefer RP Challenge Mode over agent-initiated mode.

All requests SHOULD include:
- `requestId` (client-generated stable id to correlate retries)
- `return.format` (`jwt` or `vc+json`)

### 3.3 Output

If consent can be issued immediately, tool returns:
- `structuredContent` containing the credential envelope (`schemas/happ-consent-credential.v0.3.schema.json`)
- if request input used `challenge`, returned claims MUST carry matching `challengeId`

If user interaction is required, PP SHOULD return a JSON-RPC error:
- `code: -32042`
- `data.elicitations[]` including:
  - `mode: "url"`
  - `elicitationId`
  - `url`
  - `message`

The host then navigates the user to the URL and retries the tool call after completion.

## 4. Message flow (example)

### 4.1 First call (not yet approved)
`tools/call` → error with URL elicitation required

### 4.2 User completes PoHP/identity + approves in provider UI

### 4.3 Second call (approved)
`tools/call` → returns HAPP-CC

## 5. Notes

- Sensitive interactions (biometrics, enterprise login) MUST be hosted on the PP domain (URL-mode), not in-band form fields.
- The PP MUST bind the issued credential to:
  - `intent_hash`
  - `presentation_hash`
  - `aud` (RP audience)
- For challenge-mode requests, PP MUST bind and return `claims.challengeId` equal to the supplied challenge.
