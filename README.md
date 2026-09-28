# Lua decompile pipeline

Decrypts the game's Lua TextAssets out of the patch bundles.

```powershell
pip install pycryptodome UnityPy
```

## Quick start

Run it from the directory you want the results in:

```powershell
py run_all.py
```

With no arguments it searches the current directory for its inputs and writes
`./out`. A full run takes about a minute.

## What it needs

Three inputs. All are found automatically under the current directory, and each
one can be pointed at explicitly instead.

| Flag | What it is | If omitted |
|---|---|---|
| `--metadata` | `global-metadata.dat` | searched for under `--root` |
| `--dump` | directory containing `script.json` | searched for under `--root` |
| `--assets` | tree containing the `.ua` bundles | `assetLibrary/assets`, then `assetLibrary`, then `assets`, then `.` |

> `global-metadata.dat` is **not** part of the Il2CppDumper output. It ships with
> the game at
> `com.****.****.gp/assets/bin/Data/Managed/Metadata/global-metadata.dat`.

## Flags

| Flag | Default | Meaning |
|---|---|---|
| `--root` | `.` | directory to search for inputs |
| `--work-dir` | `<root>/work` | intermediate files |
| `--out-dir` | `<root>/out` | final output |
| `--filter` | `**/*.ua` | which bundles to scan |
| `--jobs` | CPU count − 1 | worker processes |
| `--limit` | — | only process the first N bundles |
| `--quiet` | off | summary only |

## Running the stages individually

```powershell
py 01_recover_key.py     # -> <work-dir>/key.hex
py 02_extract_lua.py     # -> <out-dir>/lua/**, <out-dir>/lua_manifest.csv
py 03_verify.py          # exit 0 when the output is provably correct
```

| Stage | What it does |
|---|---|
| `01_recover_key.py` | scans the metadata for the AES key, tests candidates against a real payload lifted from a bundle |
| `02_extract_lua.py` | unwraps each bundle in memory, reads its TextAssets, decrypts, writes |
| `03_verify.py` | re-encrypts samples with PKCS#7 padding and compares against the original ciphertext |

`run_all.py` runs them in order and stops at the first failure. Flags are
forwarded to every stage, so `py run_all.py --quiet` or `py run_all.py --limit 50`
work.

## Output

| Path | Contents |
|---|---|
| `<out-dir>/lua/` | one file per decrypted TextAsset, mirroring the path stored inside the bundle |
| `<out-dir>/lua_manifest.csv` | `bundle, container, name, ciphertext_bytes, plaintext_bytes, sha256, status, text_score` |
| `<work-dir>/key.hex` | the recovered 32-byte AES key |

`status` is `lua` (recognisably Lua), `text` (decrypted to readable text but not
recognisably Lua) or `not_text`. Everything that decrypts to readable text is
written, so nothing is dropped just because it does not look like Lua.

## Running it from elsewhere

The scripts make no assumptions about where they are or where the data is:

```powershell
py C:\tools\decompile_scripts\run_all.py `
   --root D:\workspace `
   --metadata D:\workspace\com.********.********.gp\assets\bin\Data\Managed\Metadata\global-metadata.dat `
   --dump D:\workspace\dump `
   --assets D:\workspace\assetLibrary\assets `
   --out-dir D:\workspace\lua
```

## Notes

- `--filter` defaults to every `.ua` so nothing is assumed about where the Lua
  lives. Narrowing it, e.g. `--filter "luabyte/**/*.ua"`, is faster.
- Bundles are unwrapped in memory. No intermediate copy is written to disk.
- Only `01_recover_key.py` needs `--metadata` and `--dump`; the other stages need
  only `--assets` plus the key.
