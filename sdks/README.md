# HAPP SDKs

This directory contains language-specific SDKs for common HAPP verifier and hashing operations.

- `typescript/`: TypeScript SDK (`happ-sdk`)
- `python/`: Python SDK (`happ_sdk`)
- `rust/`: Rust SDK (`happ-sdk`)

Each SDK exposes a consistent core surface:

- `compute_intent_hash(action_intent)`
- `derive_signing_view(action_intent)`
- `compute_presentation_hash(signing_view)`
- `verify_claims(claims, action_intent, options)`

Notes:

- Canonicalization in these SDKs now uses RFC 8785 JCS.
- The SDK hash tests cover canonical ordering and stable hashing behavior across the three implementations.
