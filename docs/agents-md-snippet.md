# AGENTS.md snippet: Human Authorization Policy (HAPP)

This snippet is **non-normative**. It is intended as a practical policy block teams can include in an `AGENTS.md` (or similar) to teach agents when to request HAPP credentials.

```md
# Human Authorization Policy

For any action intent matching:
- payment.*, transfer.*, withdraw.*
- permissions.admin.*, iam.policy.*, access.grant.*
- data.export.*, data.delete.*, secrets.read.*
- account.recovery.*, device.enroll.*, identity.link.*

The agent MUST obtain a HAPP Consent Credential before proceeding:
- minimum PoHP: AAIF-PoHP-3
- max credential age: 120 seconds
- audience MUST match the relying party identifier (aud)

Enterprise rule:
- if the relying party requires identity binding, the agent MUST request identity.mode=required
- preferred identity scheme: entra_oidc

The agent MUST NOT modify the Action Intent after consent is collected.
The agent MUST attach the Consent Credential to the downstream request.
```
