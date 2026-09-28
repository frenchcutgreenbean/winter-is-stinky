"""Run the whole Lua pipeline in order, stopping at the first failure.

Each stage runs as its own process so a crash cannot leave the next stage
working from half-updated state, and so the exit code is meaningful.

Usage:
  python run_all.py                 # full pipeline
  python run_all.py --skip-verify   # skip the verification stage
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent

STAGES = [
    ("01_recover_key.py", "recover the AES key from global-metadata.dat"),
    ("02_extract_lua.py", "decrypt every Lua TextAsset"),
    ("03_verify.py", "verify output by re-encryption round trip"),
]


def main() -> int:
    parser = argparse.ArgumentParser(description="Run the Lua pipeline in order, stopping at the first failure.")
    parser.add_argument("--skip-verify", action="store_true", help="stop after extraction")
    parser.add_argument("--from", dest="start", help="start at this stage (e.g. 02)")
    # Anything unrecognised is forwarded verbatim to every stage, so
    # `run_all.py --quiet` or `run_all.py --limit 50` just work.
    args, extra = parser.parse_known_args()

    stages = STAGES[:2] if args.skip_verify else STAGES
    if args.start:
        stages = [s for s in stages if s[0].startswith(args.start)] or stages

    failures = 0
    for name, description in stages:
        script = HERE / name
        if not script.is_file():
            print(f"missing stage: {script}", file=sys.stderr, flush=True)
            return 1
        print("", flush=True)
        print("=" * 72, flush=True)
        print(f"{name}  -  {description}", flush=True)
        if extra:
            print(f"forwarding: {' '.join(extra)}", flush=True)
        print("=" * 72, flush=True)
        started = time.time()
        proc = subprocess.run([sys.executable, str(script), *extra])
        elapsed = time.time() - started
        if proc.returncode != 0:
            print("", flush=True)
            print(f"FAILED: {name} exited {proc.returncode} after {elapsed:.1f}s",
                  file=sys.stderr, flush=True)
            failures += 1
            break
        print(f"ok: {name} ({elapsed:.1f}s)", flush=True)

    print("", flush=True)
    if failures:
        print("pipeline FAILED", flush=True)
        return 1
    print("pipeline complete", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
