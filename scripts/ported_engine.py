"""Bridge to the unified SP-DECODE engine and its complete format catalog."""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PORT_ROOT = ROOT / "vendor" / "spdecode_python"
MAX_LOCAL_BYTES = 16 * 1024 * 1024


def formats(root: Path = ROOT) -> dict[str, str]:
    catalog = root / "vendor/spdecode_python/spdecode/data/decoder_catalog.json"
    entries = json.loads(catalog.read_text(encoding="utf-8"))["entries"]
    result = {entry["suffix"]: entry["name"] for entry in entries}
    result["solid"] = "NUR Tunnel"
    return result


def normalize_suffix(suffix: str) -> str:
    return suffix.lower().lstrip(".")


def infer_suffix(filename: str, root: Path = ROOT) -> str:
    # Longest match is necessary for .sksrv.png, not just Path.suffix == ".png".
    name = filename.lower()
    for suffix in sorted(formats(root), key=len, reverse=True):
        if name.endswith("." + suffix):
            return suffix
    return normalize_suffix(Path(filename).suffix)


def decode(data: bytes, suffix: str, *, password: str | None = None,
           hwid: str | None = None, root: Path = ROOT) -> Any:
    port_root = (root / "vendor/spdecode_python").resolve()
    if not (port_root / "spdecode/api.py").is_file():
        raise FileNotFoundError("The complete SP-DECODE package is required")
    if str(port_root) not in sys.path:
        sys.path.insert(0, str(port_root))
    from spdecode.api import decode as port_decode

    return port_decode(data, normalize_suffix(suffix), password, hwid)


def render(result: Any) -> str:
    if result is None:
        raise ValueError("Decoder produced no result")
    rendered = result if isinstance(result, str) else json.dumps(
        result, ensure_ascii=False, indent=2, default=str
    )
    if not rendered.strip():
        raise ValueError("Decoder produced an empty result")
    return rendered
