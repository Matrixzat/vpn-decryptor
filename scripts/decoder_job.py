#!/usr/bin/env python3
"""Run the unified SP-DECODE engine without exposing plaintext in job logs."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

if __package__:
    from . import ported_engine
else:
    import ported_engine


class DecoderJobError(RuntimeError):
    """Invalid configuration, missing dependency, or rejected credentials."""


def run_decoder(root: Path, input_path: Path, output_dir: Path, *,
                suffix: str | None = None, password: str | None = None,
                hwid: str | None = None) -> Path:
    selected = ported_engine.normalize_suffix(suffix) if suffix else ported_engine.infer_suffix(input_path.name, root)
    if selected not in ported_engine.formats(root):
        raise DecoderJobError("Unsupported configuration suffix")
    if not 0 < input_path.stat().st_size <= ported_engine.MAX_LOCAL_BYTES:
        raise DecoderJobError("Input must contain 1 to 16777216 bytes")
    try:
        decoded = ported_engine.decode(input_path.read_bytes(), selected, password=password, hwid=hwid, root=root)
        rendered = ported_engine.render(decoded)
    except (ImportError, FileNotFoundError):
        raise DecoderJobError("Unified decoder engine or dependency is missing") from None
    except Exception:
        raise DecoderJobError("Unified decoder rejected this configuration or its credentials") from None
    output_dir.mkdir(parents=True, exist_ok=True)
    result_path = output_dir / "result.txt"
    result_path.write_text(rendered + "\n", encoding="utf-8")
    return result_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ported_engine.ROOT)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--suffix")
    parser.add_argument("--password", help="Authorized HC or V2Box export password")
    parser.add_argument("--hwid", help="Authorized HC export HWID")
    args = parser.parse_args(argv)
    try:
        result = run_decoder(args.root.resolve(), args.input.resolve(), args.output_dir.resolve(),
                             suffix=args.suffix, password=args.password, hwid=args.hwid)
    except (OSError, DecoderJobError) as error:
        print(f"decoder job failed: {error}", file=sys.stderr)
        return 1
    print(f"decoder completed; engine=unified; result_bytes={result.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
