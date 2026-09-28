"""Verify the Lua pipeline actually produced correct output.

The strongest available check is a **round trip**: AES-ECB is deterministic, so
re-encrypting a decrypted file (with PKCS#7 padding restored) must reproduce the
original ciphertext byte for byte. If that holds, the decryption is provably
correct rather than merely plausible.

Also checks that every written file is readable text.

Inputs  work/key.hex, out/lua_manifest.csv, the bundles themselves
Output  exit code (0 = verified, 1 = something is wrong)
"""

from __future__ import annotations

import argparse
import csv
import hashlib
from pathlib import Path

from Crypto.Cipher import AES

import common


def ciphertext_for(bundle: Path, container: str) -> bytes | None:
    for entry_container, _name, blob in common.read_textassets(common.unwrap(bundle)):
        if entry_container == container:
            return blob
    return None


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify Lua output by re-encryption round trip."
    )
    common.add_path_args(parser)
    parser.add_argument("--manifest", type=Path, help="manifest written by stage 02")
    parser.add_argument("--samples", type=int, default=25, help="round-trip checks")
    parser.add_argument("--quiet", action="store_true", help="only print the result")
    args = parser.parse_args()

    root = common.root_dir(args.root)
    out_base = common.resolve_out_dir(root, args.out_dir)
    out_root = out_base / "lua"
    manifest = args.manifest or (out_base / "lua_manifest.csv")
    key = common.load_key(common.resolve_work_dir(root, args.work_dir))

    common.info(f"key      : {key.hex()}")
    if not manifest.is_file():
        common.die(f"no manifest at {manifest} - run 02_extract_lua.py first")

    with open(manifest, newline="", encoding="utf-8") as handle:
        rows = [r for r in csv.DictReader(handle) if r["status"] in ("lua", "text")]
    if not rows:
        common.die("manifest contains no decrypted rows")

    failures: list[str] = []

    # 1. every written file exists and is readable text
    if not args.quiet:
        common.info(f"checking {len(rows):,} written files ...")
    for row in rows:
        path = out_root / common.safe_relative(
            row["container"], row["name"], Path(row["bundle"])
        )
        if not path.is_file():
            failures.append(f"missing: {path}")
            continue
        blob = path.read_bytes()
        if len(blob) != int(row["plaintext_bytes"]):
            failures.append(f"size mismatch: {path}")
            continue
        if hashlib.sha256(blob).hexdigest() != row["sha256"]:
            failures.append(f"sha256 mismatch: {path}")
            continue
        if common.text_score(blob) < 0.95:
            failures.append(f"not clean text: {path}")
        elif row["status"] == "lua" and not common.looks_like_lua(blob):
            failures.append(f"manifest says lua but content disagrees: {path}")

    # 2. round-trip a spread of samples back to the exact original ciphertext
    step = max(1, len(rows) // max(1, args.samples))
    sample_rows = rows[::step][: args.samples]
    if not args.quiet:
        common.info(f"round-tripping {len(sample_rows)} samples ...")
    matched = 0
    for row in sample_rows:
        path = out_root / common.safe_relative(
            row["container"], row["name"], Path(row["bundle"])
        )
        if not path.is_file():
            continue
        original = ciphertext_for(Path(row["bundle"]), row["container"])
        if original is None:
            failures.append(f"container gone from bundle: {row['container']}")
            continue
        reencrypted = AES.new(key, AES.MODE_ECB).encrypt(common.pkcs7_pad(path.read_bytes()))
        if reencrypted == original:
            matched += 1
        else:
            failures.append(
                f"round-trip mismatch: {row['container']} "
                f"({len(reencrypted)} vs {len(original)} bytes)"
            )

    common.info("")
    common.info("=== verification ===")
    common.info(f"  files checked     : {len(rows):,}")
    common.info(f"  round-trip OK     : {matched}/{len(sample_rows)}")
    common.info(f"  problems          : {len(failures):,}")

    if failures:
        common.info("")
        for message in failures[:15]:
            common.info(f"  {message}")
        if len(failures) > 15:
            common.info(f"  ... and {len(failures) - 15} more")
        return 1

    common.info("")
    common.info("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
