"""Shared helpers for the Lua decompile pipeline.

Nothing is assumed about where anything lives. Every input is either passed
explicitly (`--metadata`, `--dump`, `--assets`) or searched for underneath
`--root`, which defaults to the current directory; outputs default to
`<root>/work` and `<root>/out`. These scripts can live anywhere and be run from
anywhere.

Game facts encoded here:

  * a bundle on disk is a zero prefix followed by a real `UnityFS` bundle, so we
    locate the signature rather than hardcoding the prefix length
  * Lua TextAsset payloads are AES-256-ECB with PKCS#7 padding
  * UnityPy returns TextAsset payloads as `str`; re-encoding with
    `surrogateescape` is what restores the exact original bytes
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterator, NoReturn

from Crypto.Cipher import AES

UNITYFS = b"UnityFS"
HEAD_SCAN = 4096              # the game's wrapper is a 27-byte zero prefix

# Every bundle is scanned by default and decryption decides what is Lua.
# Narrow it (for example --filter "luabyte/**/*.ua") for speed.
DEFAULT_FILTER = "**/*.ua"


# ------------------------------------------------------------------ logging

def info(message: str) -> None:
    print(message, flush=True)


def die(message: str, code: int = 1) -> NoReturn:
    print(f"error: {message}", file=sys.stderr, flush=True)
    raise SystemExit(code)


# --------------------------------------------------------------- locations

def add_path_args(parser: argparse.ArgumentParser) -> None:
    """Add the location flags every stage shares."""
    parser.add_argument(
        "--root", type=Path, default=Path("."),
        help="directory to search for inputs (default: the current directory)",
    )
    parser.add_argument("--metadata", type=Path, help="path to global-metadata.dat")
    parser.add_argument(
        "--dump", type=Path,
        help="Il2CppDumper output directory (the one holding script.json)",
    )
    parser.add_argument(
        "--assets", type=Path, help="asset tree that contains the .ua bundles",
    )
    parser.add_argument(
        "--work-dir", type=Path, help="intermediate files (default: <root>/work)",
    )
    parser.add_argument(
        "--out-dir", type=Path, help="final output (default: <root>/out)",
    )


def root_dir(value) -> Path:
    root = Path(value or ".").expanduser()
    if not root.is_dir():
        die(f"--root is not a directory: {root}")
    return root.resolve()


def resolve_metadata(root: Path, explicit) -> Path:
    """`global-metadata.dat` - the only place the AES key blob exists."""
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_file():
            die(f"--metadata is not a file: {path}")
        return path.resolve()
    hits = sorted(root.glob("**/global-metadata.dat"))
    if hits:
        return hits[0].resolve()
    die(f"no global-metadata.dat under {root} (pass --metadata)")


def resolve_dump_dir(root: Path, explicit) -> Path:
    """Il2CppDumper output directory - must contain `script.json`."""
    if explicit is not None:
        path = Path(explicit).expanduser()
        if path.is_file() and path.name == "script.json":
            return path.parent.resolve()
        if path.is_dir() and (path / "script.json").is_file():
            return path.resolve()
        die(f"--dump must be a directory holding script.json: {path}")
    # Prefer the conventional names, then fall back to searching.
    for name in ("new_dump", "dump"):
        candidate = root / name
        if (candidate / "script.json").is_file():
            return candidate.resolve()
    hits = sorted(p.parent for p in root.glob("**/script.json"))
    if hits:
        return hits[0].resolve()
    die(f"no script.json under {root} (pass --dump)")


def resolve_asset_root(root: Path, explicit) -> Path:
    """Root of the asset tree - the directory holding the `.ua` bundles."""
    if explicit is not None:
        path = Path(explicit).expanduser()
        if not path.is_dir():
            die(f"--assets is not a directory: {path}")
        return path.resolve()
    # Try conventional names, but only accept one that really holds bundles.
    for relative in ("assetLibrary/assets", "assetLibrary", "assets", "."):
        candidate = root / relative
        if candidate.is_dir() and next(candidate.glob("**/*.ua"), None) is not None:
            return candidate.resolve()
    die(f"no .ua bundles found under {root} (pass --assets)")


def resolve_work_dir(root: Path, explicit) -> Path:
    return Path(explicit).expanduser() if explicit else root / "work"


def resolve_out_dir(root: Path, explicit) -> Path:
    return Path(explicit).expanduser() if explicit else root / "out"


def iter_bundles(asset_root: Path, pattern: str) -> list[Path]:
    return sorted(p for p in asset_root.glob(pattern) if p.is_file())


# -------------------------------------------------------------------- crypto

def aes_decrypt(data: bytes, key: bytes) -> bytes:
    """AES-256-ECB decrypt, stripping PKCS#7 padding when it is present."""
    if not data or len(data) % 16:
        raise ValueError(f"not 16-byte aligned ({len(data)} bytes)")
    plain = AES.new(key, AES.MODE_ECB).decrypt(data)
    pad = plain[-1]
    if 1 <= pad <= 16 and plain[-pad:] == bytes([pad]) * pad:
        return plain[:-pad]
    return plain


def pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def text_score(data: bytes, sample: int = 4096) -> float:
    """Fraction of the payload that decodes as clean text (1.0 = fully readable)."""
    if not data:
        return 0.0
    chunk = data[:sample]
    try:
        text = chunk.decode("utf-8")
    except UnicodeDecodeError as exc:
        # A multi-byte character cut off at the very end is not a failure.
        if len(chunk) - exc.start <= 4 and exc.start:
            text = chunk[: exc.start].decode("utf-8", "ignore")
            if not text:
                return 0.0
        else:
            return exc.start / len(chunk)
    control = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r")
    return 1.0 - control / len(text)


# Markers present in essentially every Lua asset in this game, including the
# awkward ones: bare global assignments (`HomeLocalConfig = {}`), proto loaders
# (`assert(ProtocLib:load [[`) and files whose only `--` comment is mid-line.
LUA_MARKERS = (b"function", b"local", b"require", b"assert", b"return", b"nil", b" end", b"--")


def looks_like_lua(data: bytes, window: int = 512) -> bool:
    """Best-effort recognition. Used for labelling and key disambiguation.

    Deliberately NOT used as an extraction filter: `placeholder.bytes` decrypts
    to a bare number, which no recognition heuristic will ever call Lua, and
    dropping it would silently lose real content.
    """
    if not data:
        return False
    head = data[:window]
    if head.startswith(b"\x1bLua"):        # compiled bytecode
        return True
    return any(marker in head for marker in LUA_MARKERS)


# ------------------------------------------------------------------- bundles

def unwrap(path: Path) -> bytes:
    """Return the UnityFS bytes, skipping the game's zero-byte wrapper prefix."""
    raw = path.read_bytes()
    offset = raw[:HEAD_SCAN].find(UNITYFS)
    if offset < 0:
        raise ValueError("no UnityFS signature in the first 4096 bytes")
    return raw[offset:]


def read_textassets(bundle_bytes: bytes) -> Iterator[tuple[str, str, bytes]]:
    """Yield `(container, name, payload)` for each TextAsset in a bundle."""
    import UnityPy  # deferred: importing it is slow and only needed here

    env = UnityPy.load(bundle_bytes)
    for obj in env.objects:
        if obj.type.name != "TextAsset":
            continue
        try:
            data = obj.read()
        except Exception:
            continue
        raw = getattr(data, "m_Script", None)
        if isinstance(raw, str):
            raw = raw.encode("utf-8", "surrogateescape")
        if not isinstance(raw, (bytes, bytearray)):
            continue
        try:
            container = str(obj.container or "")
        except Exception:
            container = ""
        yield container, str(getattr(data, "m_Name", "") or ""), bytes(raw)


def safe_relative(container: str, name: str, bundle: Path) -> Path:
    """Turn a container path into a safe relative output path."""
    text = (container or name or bundle.stem).replace("\\", "/").lstrip("/")
    parts = [p for p in text.split("/") if p not in ("", ".", "..")]
    if not parts:
        parts = [bundle.stem]
    if parts[-1].endswith(".bytes"):
        parts[-1] = parts[-1][: -len(".bytes")]
    if not parts[-1].endswith(".lua"):
        parts[-1] += ".lua"
    return Path(*parts)


# ----------------------------------------------------------------------- key

def key_file(work_dir: Path) -> Path:
    return Path(work_dir) / "key.hex"


def save_key(work_dir: Path, key: bytes) -> Path:
    path = key_file(work_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(key.hex() + "\n", encoding="ascii")
    return path


def load_key(work_dir: Path) -> bytes:
    path = key_file(work_dir)
    if not path.is_file():
        die(f"no key at {path} - run 01_recover_key.py first")
    try:
        key = bytes.fromhex(path.read_text(encoding="ascii").strip())
    except ValueError as exc:
        die(f"key at {path} is not valid hex: {exc}")
    if len(key) not in (16, 24, 32):
        die(f"key at {path} has invalid length {len(key)}")
    return key
