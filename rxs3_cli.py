#!/usr/bin/env python3
"""Isolated-mode launcher: import only this root-owned installation."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from rxs3.cli import entry

if __name__ == '__main__':
    raise SystemExit(entry())
