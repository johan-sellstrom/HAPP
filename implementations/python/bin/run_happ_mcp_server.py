#!/usr/bin/env python3
from __future__ import annotations

import os, sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import argparse

from happ.mcp.stdio_server import run_stdio


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ui-port", type=int, default=8787)
    args = ap.parse_args()
    run_stdio(ui_port=args.ui_port)


if __name__ == "__main__":
    main()
