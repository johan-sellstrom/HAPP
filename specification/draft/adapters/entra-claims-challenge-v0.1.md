# HAPP Optional Transport Profile: Microsoft Entra Claims Challenge (`entra_claims_challenge`) v0.1

**Status:** Draft  
**Profile ID:** `aaif.happ.profile.entra-claims-challenge/v0.1`  
**Applies to:** HAPP v0.3.x  
**Companion adapter:** `entra_oidc`

## 1. Purpose

This profile defines how a Presence Provider (PP) may satisfy a HAPP step-up using **Microsoft Entra claims challenge** semantics. It does not create a new identity binding scheme. Instead, it reuses the existing `entra_oidc` adapter and specifies how a PP carries an Entra `claims` request through the OAuth 2.0 Authorization Code + PKCE flow before issuing a HAPP Consent Credential.

The profile is intended for enterprise environments where the relying party or bridge already uses Microsoft Entra Conditional Access / authentication context and wants that stronger proof to be part of the HAPP approval ceremony.

## 2. Inputs

The PP MAY receive Entra claims-challenge requirements through either of these extension points:

- `requirements.identity.policy.entraClaimsChallenge`
- `requirements.identity.schemeParams.entra_claims_challenge`

The value MAY be:
- a decoded JSON object suitable for the OAuth `claims` parameter, or
- a raw JSON string already prepared for the `claims` parameter.

If no explicit claims challenge is supplied, the PP MAY derive one from existing identity policy inputs such as:
- `requireMfa`
- `requiredAuthContexts`

## 3. PP behavior

A PP claiming this profile:

1. **MUST** execute the Entra identity-binding flow using Authorization Code + PKCE.
2. **MUST** preserve `state`, `nonce`, and PKCE binding in the same HAPP consent session.
3. **MUST** include the Entra `claims` parameter on the authorization request when an explicit or derived claims challenge is present.
4. **SHOULD** include client capability signaling (`xms_cc=cp1`) when talking to Entra resources that require claims-challenge-capable clients.
5. **MUST NOT** treat the refreshed Entra token as a substitute for HAPP consent. The HAPP Consent Credential remains the approval artifact; the refreshed token is enterprise identity evidence supporting the approval.
6. **SHOULD** record the effective claims request in session debug or evidence metadata for auditability.

## 4. RP behavior

An RP or bridge claiming this profile:

1. **MAY** request an explicit Entra claims challenge using one of the extension fields above.
2. **SHOULD** require embedded evidence if it must directly verify the refreshed Entra identity token.
3. **MUST** continue to verify the resulting HAPP Consent Credential in full, including `intent_hash`, `presentation_hash`, audience, expiry, replay controls, and identity binding.
4. **MUST NOT** accept the presence of a refreshed Entra token as proof of human approval on its own.

## 5. Example requirements block

```json
{
  "identity": {
    "mode": "required",
    "schemes": ["entra_oidc"],
    "policy": {
      "requireEmbeddedEvidence": true,
      "requireMfa": true,
      "requiredAuthContexts": ["c1"],
      "entraClaimsChallenge": {
        "id_token": {
          "acrs": {
            "essential": true,
            "values": ["c1"]
          }
        },
        "access_token": {
          "xms_cc": {
            "values": ["cp1"]
          }
        }
      }
    }
  }
}
```

## 6. Security notes

- The Entra claims challenge is a transport for stronger enterprise identity proof; it is not the HAPP approval artifact.
- Session continuity (`state`, `nonce`, PKCE, `challengeId`) remains mandatory.
- The profile is vendor-specific and optional; it should be claimed only when an implementation actually supports it.
