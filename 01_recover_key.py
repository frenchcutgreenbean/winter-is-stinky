"""Recover the AES-256 key that encrypts the game's Lua TextAssets.

Why this works
--------------
IL2CPP compiles C# `byte[]` literals into fields of a compiler-generated
`<PrivateImplementationDetails>` class. Each field is *named after the SHA-256
of its own contents*, so the metadata gives us the hash but not the bytes.

We recover the bytes by sliding a 32-byte window across `global-metadata.dat`
and hashing until the digest equals a known field name. The window that matches
*is* the literal - this is a self-verifying search, not a brute force.

A hash match alone is not enough: several 32-byte literals match. So each
candidate is then tried as an AES-256-ECB key against a real ciphertext sample
lifted straight out of a bundle. Exactly one decrypts into readable Lua.

Nothing here is hardcoded to a particular file: the sample is discovered from
the asset tree, so the script works on a fresh extract.

Inputs  global-metadata.dat, <dump>/script.json, any bundle under --assets
Output  work/key.hex
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from Crypto.Cipher import AES

import common

WINDOW = 32
PROBE_BYTES = 256      # a block-aligned prefix is enough to judge a candidate key
BUNDLE_CAP = 2000      # give up after probing this many bundles


def load_field_names(script_json: Path) -> set[str]:
    """SHA-256 names of `<PrivateImplementationDetails>` field literals."""
    data = json.loads(script_json.read_text(encoding="utf-8"))
    names: set[str] = set()
    for entry in data.get("ScriptMetadata", []):
        name = entry.get("Name", "")
        if not name.startswith("Field$<PrivateImplementationDetails>."):
            continue
        digest = name.rsplit(".", 1)[-1]
        if len(digest) == 64:
            names.add(digest.upper())
    return names


def _scan_range(path: str, start: int, stop: int, names: frozenset[str]) -> list[tuple[int, bytes]]:
    with open(path, "rb") as handle:
        handle.seek(start)
        data = handle.read(stop - start + WINDOW)
    found: list[tuple[int, bytes]] = []
    for offset in range(start, stop):
        window = data[offset - start : offset - start + WINDOW]
        if len(window) < WINDOW:
            break
        if hashlib.sha256(window).hexdigest().upper() in names:
            found.append((offset, window))
    return found


def scan_metadata(path: Path, names: set[str], jobs: int) -> list[tuple[int, bytes]]:
    limit = path.stat().st_size - WINDOW + 1
    span = limit // jobs + 1
    ranges = [(start, min(start + span, limit)) for start in range(0, limit, span)]
    frozen = frozenset(names)
    hits: list[tuple[int, bytes]] = []
    with ProcessPoolExecutor(max_workers=jobs) as pool:
        futures = [pool.submit(_scan_range, str(path), s, e, frozen) for s, e in ranges]
        for future in futures:
            hits.extend(future.result())
    return hits


def probe_of(blob: bytes) -> bytes | None:
    """A short, block-aligned prefix of a payload - enough to judge a key cheaply."""
    if len(blob) < PROBE_BYTES or len(blob) % 16:
        return None
    return blob[:PROBE_BYTES]


def key_matches(key: bytes, probe: bytes) -> bool:
    """A correct key turns ciphertext into readable Lua within the first blocks."""
    plain = AES.new(key, AES.MODE_ECB).decrypt(probe)
    window = len(plain)
    return (
        common.text_score(plain, sample=window) >= 0.9
        and common.looks_like_lua(plain, window=window)
    )


def find_key(candidates: list[tuple[int, bytes]], asset_root: Path, pattern: str,
             cap: int = BUNDLE_CAP):
    """Try every candidate key against real payloads until one decrypts.

    Deliberately assumes nothing about which directory holds the encrypted Lua:
    it walks bundles in sorted order and tests each payload it meets, stopping
    at the first key that produces readable Lua.
    """
    scanned = payloads = 0
    for path in common.iter_bundles(asset_root, pattern):
        if scanned >= cap:
            break
        scanned += 1
        try:
            entries = list(common.read_textassets(common.unwrap(path)))
        except Exception:
            continue
        for container, name, blob in entries:
            probe = probe_of(blob)
            if probe is None:
                continue
            payloads += 1
            for offset, key in candidates:
                if key_matches(key, probe):
                    return (offset, key, path, container, name, blob), scanned, payloads
    return None, scanned, payloads


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recover the AES-256 key for the game's Lua TextAssets."
    )
    common.add_path_args(parser)
    parser.add_argument("--filter", default=common.DEFAULT_FILTER, help="glob for bundles")
    parser.add_argument("--jobs", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    root = common.root_dir(args.root)
    metadata = common.resolve_metadata(root, args.metadata)
    dump_dir = common.resolve_dump_dir(root, args.dump)
    asset_root = common.resolve_asset_root(root, args.assets)
    work_dir = common.resolve_work_dir(root, args.work_dir)

    names = load_field_names(dump_dir / "script.json")
    if not names:
        common.die(f"no <PrivateImplementationDetails> names in {dump_dir / 'script.json'}")

    common.info(f"root      : {root}")
    common.info(f"metadata  : {metadata} ({metadata.stat().st_size:,} bytes)")
    common.info(f"dump dir  : {dump_dir}  ({len(names)} SHA-256 field names)")
    common.info(f"assets    : {asset_root}")
    common.info(f"scanning  : {args.jobs} workers, sliding {WINDOW}-byte window")
    hits = scan_metadata(metadata, names, args.jobs)

    unique: dict[bytes, int] = {}
    for offset, blob in hits:
        unique.setdefault(blob, offset)
    common.info(f"candidates: {len(hits)} windows matched, {len(unique)} unique blobs")

    if not unique:
        common.die(
            "no metadata window matched a known field name - "
            "check --metadata and --dump point at the matching build"
        )

    candidates = sorted(
        ((offset, blob) for blob, offset in unique.items()), key=lambda item: item[0]
    )
    hit, scanned, payloads = find_key(candidates, asset_root, args.filter)

    if hit is None:
        common.die(
            f"none of the {len(candidates)} candidate keys decrypted any of the "
            f"{payloads} payload(s) found across {scanned} bundle(s) under {asset_root} - "
            "check --assets/--filter, or the scheme may not be AES-256-ECB"
        )

    offset, key, bundle, container, name, blob = hit
    plain = common.aes_decrypt(blob, key)
    common.info(f"probed    : {scanned} bundle(s), {payloads} payload(s)")
    common.info(f"sample    : {container or name or bundle.name} ({len(blob)} bytes)")
    common.info("")
    common.info(f"*** KEY RECOVERED *** offset=0x{offset:x}")
    common.info(f"    key: {key.hex()}")
    common.info(f"    sample decrypts to {len(plain):,} bytes of text")
    if not args.quiet:
        head = plain[:100].decode("utf-8", "replace").splitlines()[0]
        common.info(f"    head: {head}")
    path = common.save_key(work_dir, key)
    common.info(f"    saved to {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
