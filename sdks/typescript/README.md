# HAPP TypeScript SDK

TypeScript utilities for HAPP hashing and claim verification.

## Install

```bash
npm install happ-sdk
```

## Test

```bash
npm test
```

## Usage

```ts
import { computeIntentHash, deriveSigningView, computePresentationHash, verifyClaims } from "happ-sdk";

const intentHash = computeIntentHash(actionIntent);
const view = deriveSigningView(actionIntent);
const presentationHash = computePresentationHash(view);

verifyClaims(claims, actionIntent, {
  expectedAud: "did:web:rp.example",
  minPoHpLevel: "AAIF-PoHP-3",
  identityRequired: true
});
```

## Notes

- Deterministic JSON canonicalization is used in this SDK for compatibility with this repository.
- Strict production deployments should use RFC 8785 JCS canonicalization.
