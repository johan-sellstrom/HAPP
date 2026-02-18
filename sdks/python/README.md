# HAPP Python SDK

Python utilities for HAPP hashing and claim verification.

## Install

```bash
pip install happ-sdk
```

## Test

```bash
PYTHONPATH=src python -m unittest discover -s tests
```

## Usage

```python
from happ_sdk import (
    compute_intent_hash,
    derive_signing_view,
    compute_presentation_hash,
    verify_claims,
)

intent_hash = compute_intent_hash(action_intent)
view = derive_signing_view(action_intent)
presentation_hash = compute_presentation_hash(view)

claims = verify_claims(
    claims,
    action_intent,
    expected_aud="did:web:rp.example",
    min_pohp_level="AAIF-PoHP-3",
    identity_required=True,
)
```

## Notes

- Deterministic JSON canonicalization is used in this SDK for compatibility with this repository.
- Strict production deployments should use RFC 8785 JCS canonicalization.
