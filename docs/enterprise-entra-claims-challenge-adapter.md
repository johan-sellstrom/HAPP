# Enterprise integration: Microsoft Entra claims challenge transport

This note describes how HAPP can satisfy an enterprise step-up by reusing Microsoft Entra **claims challenge** semantics.

The pattern is:

1. RP or bridge determines that stronger enterprise proof is needed.
2. RP or bridge passes an Entra claims request into HAPP using `requirements.identity.policy.entraClaimsChallenge` or `schemeParams.entra_claims_challenge`.
3. The Presence Provider reuses the existing `entra_oidc` adapter, but sends the OAuth 2.0 `/authorize` request with the Entra `claims` parameter.
4. The refreshed Entra token becomes enterprise identity evidence bound to the same HAPP approval session.
5. HAPP still issues the Consent Credential, and the RP still verifies HAPP as the approval artifact.

This lets enterprise deployments benefit from existing Conditional Access / auth-context policies without making Entra the core HAPP transport.
