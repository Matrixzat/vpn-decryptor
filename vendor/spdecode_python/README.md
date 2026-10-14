# SP-DECODE 1.1.4 — Python decoder ports

This package contains **76 individual Python decoder entry points for all 239 suffixes in the APK catalog**, plus **one additional NUR `.solid` script** exposed separately by the app: **77 decoder scripts in total**. It also includes shared Python engines, recovered materials, and validation tests. The Python, PHP and JavaScript paths recorded by the APK have each been assigned a `.py` entry point in `decoders/`.

These are newly written ports of the recovered Android implementation, not the original author's Python sources. Scripts share the sibling `spdecode/` package; keep that directory with them. Running the decoders requires Python and the listed dependencies, but no Java or Android runtime.

## Install and run

Use Python 3.10 or later. Extract the archive and open a terminal in its root:

```sh
python -m pip install -r requirements.txt
python decode.py --list
python decoders/TLS.py exported_config.tls -o decoded.json
python decoders/ultra.py exported_config.ultratunnel -o decoded.json
python decoders/renz.py exported_config.7net -o decoded.json
```

You can also select a format explicitly when the filename has a different extension:

```sh
python decode.py input.bin --suffix tls -o decoded.json
python decode.py input.bin --suffix hc --password YOUR_PASSWORD --hwid YOUR_HWID
```

The HTTP Custom password/HWID options supply credentials required by protected exports. The original APK's V2Box decoder does not decode exports protected with a user-defined password; that limitation remains in this port.

## Python API

```python
from pathlib import Path
from spdecode.api import decode

result = decode(Path("exported_config.tls").read_bytes(), "tls")
```

Each entry-point script also exposes `decode(data, suffix=None, password=None, hwid=None)`. Supply `suffix` for scripts handling several aliases. `decoder_index.json` records the exact script-to-suffix mapping.

## Engines and recovered materials

| Family | Registered suffixes | Shared Python engine |
|---|---:|---|
| Generic AES/DES | 81 | `spdecode/families.py` |
| Ultra / Argon2id | 41 | `spdecode/families.py` |
| Renz / custom XXTEA / Threefish | 16 | `spdecode/renz.py` |
| Special formats | 27 | `spdecode/special.py` |
| Independent / Flex / IZPH | 13 | `spdecode/independent.py` |
| Legacy formats | 61 | `legacy.py`, `batch_legacy.py`, `injector.py`, `whitebox.py`, `httpcustom.py`, `linklayer.py`, `misc.py` |

The decrypted profiles, passwords, keys, aliases and whitebox tables are in `spdecode/data/`. These are the exact recovered materials from the supplied APK. The extra `.solid` decoder is `decoders/nur_tunnel_solid.py`; the shared CLI/API also accepts it because the app exposes it outside the 239-entry catalog.

Decoder results use JSON structures or raw text, rather than the Android app's decorative banners, emojis and translated display labels. The app's displayed field filtering and formatting are not reproduced byte for byte; keeping raw fields preserves more of the decoded data.

## Validation

Run:

```sh
python tests/test_ports.py
```

The included suite checks synthetic configurations for all generic profiles, Ultra profiles with registered aliases, all Renz aliases, six TLS key profiles, Flex versions 1–4, XOR aliases, selected legacy and independent formats, and complete EHI, LinkLayer, sealed HCCFG and NPVS containers. It checks rejection of modified authenticated data and verifies catalog routing for all 239 suffixes. The latter is a routing check, not a successful-decryption test for every suffix.

NPV and NPVS whitebox outputs and both Threefish permutation variants match reference Java code extracted from the APK. `tests/Reference.java` and `tests/reference_vectors.txt` preserve those comparisons. Java is needed only to regenerate those reference vectors; ordinary tests use the saved vectors.

## Compatibility status

**All ports are experimental. No real exported configuration files were supplied, so real exporter compatibility is not certified.** Synthetic tests establish the paths they exercise, not every historical file variant or every nested field case. In particular, complex EHI/EHIL, IZPH, N4 and Renz nested fields were reconstructed from decompiled code containing warnings and need real-file checks.

HTTP Custom reproduces the recovered APK's historical unauthenticated outer-envelope and stream formats as well as its newer authenticated formats. A successful legacy decode is not evidence of an authentication tag check. Newer authenticated container paths retain their tag, signature and inventory checks.

This package does not include Android UI, file history, online catalog downloading or a rebuilt APK. A decode failure can mean a wrong suffix, missing required credentials, damaged data or an unsupported/incorrectly reconstructed variant. Test known exports before relying on a port's output.
