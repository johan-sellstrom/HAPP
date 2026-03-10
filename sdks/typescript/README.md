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

- Hashes in this SDK now use RFC 8785 JCS canonicalization.
- Unsupported JSON inputs such as `undefined`, functions, symbols, `bigint`, and non-finite numbers are rejected before hashing.
