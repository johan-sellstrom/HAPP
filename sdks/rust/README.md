# HAPP Rust SDK

Rust utilities for HAPP hashing and claim verification.

## Add dependency

```toml
[dependencies]
happ-sdk = "0.1"
```

## Usage

```rust
use happ_sdk::{compute_intent_hash, derive_signing_view, compute_presentation_hash, verify_claims};
```

## Notes

- Hashes in this SDK now use RFC 8785 JCS canonicalization.
- Hash stability is tested directly against canonicalization behavior instead of relying only on verifier tests.
