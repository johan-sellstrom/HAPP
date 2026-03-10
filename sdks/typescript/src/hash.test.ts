import { strict as assert } from "node:assert";
import { test } from "node:test";

import { canonicalJson, sha256Prefixed } from "./index.js";

const sampleValue = {
  z: [3, null, "A\u000f"],
  b: 1,
  a: {
    d: 4.5,
    c: 0.002,
    e: 1e30,
  },
};

test("canonicalJson uses RFC 8785 JCS", () => {
  assert.equal(
    canonicalJson(sampleValue),
    '{"a":{"c":0.002,"d":4.5,"e":1e+30},"b":1,"z":[3,null,"A\\u000f"]}',
  );
});

test("sha256Prefixed is stable across object key order", () => {
  const left = {
    b: 1,
    a: {
      d: 4.5,
      c: 0.002,
      e: 1e30,
    },
  };
  const right = {
    a: {
      c: 0.002,
      e: 1e30,
      d: 4.5,
    },
    b: 1,
  };

  assert.equal(sha256Prefixed(left), sha256Prefixed(right));
});

test("canonicalJson rejects non-finite numbers", () => {
  assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }), /finite numbers/);
});

test("canonicalJson rejects undefined members", () => {
  assert.throws(() => canonicalJson({ value: undefined }), /not valid JSON/);
});
