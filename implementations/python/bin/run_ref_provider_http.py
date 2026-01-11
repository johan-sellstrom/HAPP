#!/usr/bin/env python3
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse

from happ.provider.http_server import run_http


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8766)
    args = ap.parse_args()
    run_http(port=args.port)


if __name__ == "__main__":
    main()
