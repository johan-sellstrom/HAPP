from __future__ import annotations

import unittest

from happ_sdk import FloatDomainError, canonical_json, sha256_prefixed


class HashTests(unittest.TestCase):
    def test_canonical_json_uses_rfc8785_jcs(self):
        value = {
            "z": [3, None, "A\u000f"],
            "b": 1,
            "a": {
                "d": 4.5,
                "c": 0.002,
                "e": 1e30,
            },
        }

        self.assertEqual(
            canonical_json(value),
            '{"a":{"c":0.002,"d":4.5,"e":1e+30},"b":1,"z":[3,null,"A\\u000f"]}',
        )

    def test_sha256_prefixed_is_stable_across_object_key_order(self):
        left = {
            "b": 1,
            "a": {
                "d": 4.5,
                "c": 0.002,
                "e": 1e30,
            },
        }
        right = {
            "a": {
                "c": 0.002,
                "e": 1e30,
                "d": 4.5,
            },
            "b": 1,
        }

        self.assertEqual(sha256_prefixed(left), sha256_prefixed(right))

    def test_canonical_json_rejects_non_finite_numbers(self):
        with self.assertRaises(FloatDomainError):
            canonical_json({"value": float("inf")})


if __name__ == "__main__":
    unittest.main()
