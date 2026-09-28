"""Decrypt every Lua TextAsset out of the patch bundles.

This is the payoff stage: it walks the `.ua` bundles, strips the wrapper, reads
each TextAsset, decrypts it with the recovered key, and writes the result.

Output mirrors the bundle's own container path, so the layout is deterministic
and collision-free (the old flat `lua/` dump had name clashes because it derived
filenames from strings embedded inside the Lua).

Inputs  bundles under --assets, work/key.hex
Output  out/lua/<container path>.lua, out/lua_manifest.csv
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

import common

LUA = "lua"            # decrypts to text that is recognisably Lua
TEXT = "text"          # decrypts to text, but not recognisably Lua (still kept)
NOT_TEXT = "not_text"  # does not decrypt to readable text at all
TEXT_MIN = 0.90


def process_bundle(task: tuple[str, str, str]) -> dict:
    """Worker: decrypt the Lua TextAssets of one bundle."""
    bundle_str, key_hex, out_root_str = task
    bundle = Path(bundle_str)
    key = bytes.fromhex(key_hex)
    out_root = Path(out_root_str)

    result: dict = {"bundle": bundle_str, "rows": [], "errors": []}

    try:
        payloads = list(common.read_textassets(common.unwrap(bundle)))
    except Exception as exc:
        result["errors"].append(f"{bundle_str}: {type(exc).__name__}: {exc}")
        return result

    for index, (container, name, blob) in enumerate(payloads):
        if not blob:
            continue
        try:
            plain = common.aes_decrypt(blob, key)
        except Exception:
            result["rows"].append(
                (bundle_str, container, name, len(blob), 0, "", NOT_TEXT, 0.0)
            )
            continue

        # The key was recovered from this very tree, so a payload that decrypts
        # to readable text is a success. Whether it *looks* like Lua is recorded
        # for filtering, never used to discard - a few assets are plain data and
        # a heuristic would silently drop them.
        score = common.text_score(plain)
        if score < TEXT_MIN:
            result["rows"].append(
                (bundle_str, container, name, len(blob), len(plain), "", NOT_TEXT,
                 round(score, 4))
            )
            continue

        relative = common.safe_relative(container, name or f"asset{index}", bundle)
        destination = out_root / relative
        digest = hashlib.sha256(plain).hexdigest()
        try:
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(plain)
        except OSError as exc:
            result["errors"].append(f"{destination}: {exc}")
            continue

        status = LUA if common.looks_like_lua(plain) else TEXT
        result["rows"].append(
            (bundle_str, container, name, len(blob), len(plain), digest, status,
             round(score, 4))
        )

    return result


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt every Lua TextAsset out of the patch bundles."
    )
    common.add_path_args(parser)
    parser.add_argument("--filter", default=common.DEFAULT_FILTER, help="glob for bundles")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--limit", type=int, help="only process the first N bundles")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    root = common.root_dir(args.root)
    asset_root = common.resolve_asset_root(root, args.assets)
    out_base = common.resolve_out_dir(root, args.out_dir)
    key = common.load_key(common.resolve_work_dir(root, args.work_dir))

    bundles = common.iter_bundles(asset_root, args.filter)
    if args.limit:
        bundles = bundles[: args.limit]
    if not bundles:
        common.die(f"no bundles matched {args.filter!r} under {asset_root}")

    out_root = out_base / "lua"
    out_root.mkdir(parents=True, exist_ok=True)

    common.info(f"root      : {root}")
    common.info(f"asset root: {asset_root}")
    common.info(f"bundles   : {len(bundles):,} matching {args.filter!r}")
    common.info(f"workers   : {args.jobs}")
    common.info(f"output    : {out_root}")

    tasks = [(str(p), key.hex(), str(out_root)) for p in bundles]
    rows: list[tuple] = []
    errors: list[str] = []

    done = 0
    with ProcessPoolExecutor(max_workers=args.jobs) as pool:
        for result in pool.map(process_bundle, tasks):
            done += 1
            rows.extend(result["rows"])
            errors.extend(result["errors"])
            if not args.quiet and done % 500 == 0:
                common.info(f"  ... {done:,}/{len(bundles):,}")

    written = [r for r in rows if r[6] in (LUA, TEXT)]
    lua_rows = [r for r in rows if r[6] == LUA]
    text_rows = [r for r in rows if r[6] == TEXT]
    skipped = [r for r in rows if r[6] == NOT_TEXT]

    manifest = out_base / "lua_manifest.csv"
    manifest.parent.mkdir(parents=True, exist_ok=True)
    with open(manifest, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            ["bundle", "container", "name", "ciphertext_bytes", "plaintext_bytes",
             "sha256", "status", "text_score"]
        )
        writer.writerows(sorted(rows))

    common.info("")
    common.info("=== summary ===")
    common.info(f"  bundles processed : {len(bundles):,}")
    common.info(f"  TextAssets seen   : {len(rows):,}")
    common.info(f"  written as .lua   : {len(lua_rows):,}")
    common.info(f"  written as data   : {len(text_rows):,}  (text, not recognisably Lua)")
    common.info(f"  not readable text : {len(skipped):,}")
    common.info(f"  errors            : {len(errors):,}")
    common.info(f"  manifest          : {manifest}")

    if errors:
        common.info("")
        common.info("first errors:")
        for message in errors[:10]:
            common.info(f"  {message}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
