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

- Deterministic JSON canonicalization is used in this SDK for compatibility with this repository.
- Strict production deployments should use RFC 8785 JCS canonicalization.
