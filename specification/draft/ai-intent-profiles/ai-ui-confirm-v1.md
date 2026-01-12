# Annex: HAPP Integration (Optional) — Update for `ai_ui_confirm_v1`
If your AG-UI Mobile Profile (or any other UI profile) integrates with HAPP, it SHOULD target the general HAPP AI-INTENT profile `ai_ui_confirm_v1`.

## What changes vs the earlier mobile-specific mapping?
- The HAPP profile is UI-agnostic; your UI protocol only needs to map its confirm/approval primitive into the `ui` block.
- The same `confirm` UX works on mobile, desktop, web, or embedded surfaces.

## Minimal mapping guidance
- confirmation title/heading → `ui.title`
- action label → `ui.label`
- effects list (ordered) → `ui.effects[]`
- permissions/scopes (if used) → `ui.permissions[]`
- risk level → `ui.risk`
- undo/mitigation → `ui.reversibility`
- locale/timezone → `ui.locale`, `ui.timezone`

Everything else (how you notify, deep-link, or handoff) stays specific to your client platform.
