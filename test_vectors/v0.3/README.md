# Test vectors (HAPP v0.3)

These vectors are intended to validate that different implementations agree on:

- `intent_hash` computation for an Action Intent
- `presentation_hash` computation for a derived Signing View

Important note on canonicalization:

- The HAPP specification requires RFC 8785 (JCS) canonicalization for hashing.
- The **reference implementation** included in this repository uses a deterministic JSON encoding
  (sorted keys, compact separators) as a pragmatic stand-in for JCS.

If you use a true RFC 8785 JCS library, your hashes may differ from these vectors unless you match
the exact canonicalization approach.

These vectors are therefore most useful for validating interoperability with the reference code in
`implementations/python/happ/`.
