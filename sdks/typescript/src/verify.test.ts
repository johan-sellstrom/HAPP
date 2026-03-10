import { strict as assert } from "node:assert";
import { test } from "node:test";

import { computeIntentHash, computePresentationHash, deriveSigningView, verifyClaims } from "./index.js";
import type { ActionIntent, HappClaims } from "./types.js";

const actionIntent: ActionIntent = {
  profile: "aaif.happ.profile.generic/v0.3",
  audience: { id: "did:web:rp.example", name: "RP" },
  agent: { id: "agent:1", name: "Agent" },
  action: { type: "consent" },
};

function makeClaims(overrides: Partial<HappClaims> = {}): HappClaims {
  const view = deriveSigningView(actionIntent);
  return {
    aud: "did:web:rp.example",
    exp: 4_102_444_800,
    intent_hash: computeIntentHash(actionIntent),
    presentation_hash: computePresentationHash(view),
    assurance: { level: "AAIF-PoHP-3" },
    ...overrides,
  };
}

test("verifyClaims accepts valid claims", () => {
  const claims = makeClaims();
  const verified = verifyClaims(claims, actionIntent, {
    expectedAud: "did:web:rp.example",
    minPoHpLevel: "AAIF-PoHP-2",
    nowEpochSeconds: 1_700_000_000,
  });
  assert.equal(verified.aud, "did:web:rp.example");
});

test("verifyClaims rejects expired claims", () => {
  const claims = makeClaims({ exp: 10 });
  assert.throws(
    () =>
      verifyClaims(claims, actionIntent, {
        expectedAud: "did:web:rp.example",
        nowEpochSeconds: 100,
      }),
    /expired/,
  );
});

test("verifyClaims rejects invalid PoHP policy levels", () => {
  const claims = makeClaims();
  assert.throws(
    () =>
      verifyClaims(claims, actionIntent, {
        expectedAud: "did:web:rp.example",
        minPoHpLevel: "NOT-A-REAL-LEVEL" as never,
      }),
    /invalid PoHP level/,
  );
});
