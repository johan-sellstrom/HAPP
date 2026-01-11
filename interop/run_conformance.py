#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, Optional

import requests


ROOT = Path(__file__).resolve().parent
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)


SAMPLE_ACTION_INTENT = {
  "version": "0.3",
  "intentId": "550e8400-e29b-41d4-a716-446655440000",
  "issuedAt": "2026-01-09T12:00:00Z",
  "profile": "aaif.happ.profile.payment.transfer/v0.3",
  "audience": {"id": "did:web:bank.example", "name": "Example Bank"},
  "agent": {"id": "did:web:agent.example", "name": "Finance Agent", "software": {"name": "ExampleAgent", "version": "1.0.0"}},
  "action": {"type": "payment.transfer", "parameters": {"amount": {"currency": "GBP", "value": "250.00"}, "to": {"iban": "GB00TEST"}, "reference": "Invoice 18372"}},
  "constraints": {"expiresAt": "2026-01-09T12:02:00Z", "oneTime": True},
  "display": {"language": "en", "title": "Approve payment", "summary": "Approve a £250 transfer to GB00TEST (Invoice 18372).", "riskNotice": "Money will move immediately."}
}


def fetch_from_http_sut(base_url: str) -> Dict[str, Any]:
    # Ask the SUT to issue a credential with Entra identity binding.
    payload = {
        "issuer": "did:web:pp.sut",
        "actionIntent": SAMPLE_ACTION_INTENT,
        "requirements": {
            "pohp": {"minLevel": "AAIF-PoHP-3", "maxCredentialAgeSeconds": 120},
            "identity": {"mode": "required", "schemes": ["entra_oidc"], "policy": {"requireEmbeddedEvidence": True}},
        },
        # Provide a mock identity binding so any compliant SUT can accept it.
        # Real SUTs can ignore this and compute their own binding; tests will verify output.
        "identityBinding": {
            "mode": "verified",
            "scheme": "entra_oidc",
            "idp": {"issuer": "https://login.microsoftonline.com/mock/v2.0", "tenantId": "00000000-0000-0000-0000-000000000000"},
            "subject": {"type": "entra_oid_tid", "tid": "00000000-0000-0000-0000-000000000000", "oid": "11111111-1111-1111-1111-111111111111"},
            "evidence": {"embedded": False}
        },
        "ttlSeconds": 120
    }
    r = requests.post(base_url.rstrip("/") + "/issue", json=payload, timeout=10)
    r.raise_for_status()
    return r.json()["credential"]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sut", default="", help="Optional SUT. Use 'http://127.0.0.1:8766' to fetch live credentials.")
    ap.add_argument("--junit", default=str(RESULTS / "junit.xml"))
    args = ap.parse_args()

    if args.sut:
        if args.sut.startswith("http"):
            cred = fetch_from_http_sut(args.sut)
            out = RESULTS / "sut_credential.json"
            out.write_text(json.dumps({"actionIntent": SAMPLE_ACTION_INTENT, "credential": cred}, indent=2), encoding="utf-8")
            os.environ["HAPP_SUT_FILE"] = str(out)

    cmd = [sys.executable, "-m", "pytest", "-q", str(ROOT / "tests"), f"--junitxml={args.junit}"]
    print("Running:", " ".join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        sys.exit(rc)

    print("\nConformance OK. JUnit:", args.junit)


if __name__ == "__main__":
    main()
