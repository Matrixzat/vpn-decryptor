#!/usr/bin/env python3
"""Run one checked-in configuration decoder without exposing plaintext in logs."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


DECODER_CANDIDATES: dict[str, tuple[str, ...]] = {
    ".ehi": ("HttpInjector.py", "httpinjector.py", "ehi_decoder.py"),
    ".npvt": ("NPVTunnel.py", "npvtunnel.py", "npvt_decoder.py"),
    ".hc": ("HTTP_Custom.py", "http_custom.py", "httpcustom_decoder.py"),
    ".dark": ("darktunnel_decoder.py",),
    ".nm": ("netmod_decoder.py",),
    ".sip": ("SocksIP.py", "socksip.py"),
    ".tnl": ("tnl_decoder.py",),
    ".ziv": ("ZIVPN.py", "zivpn.py"),
    ".hat": ("Ha_Tunnel.py", "ha_tunnel.py"),
}


class DecoderJobError(RuntimeError):
    """Raised for an invalid request or decoder failure."""


def _find_decoder(root: Path, suffix: str) -> Path:
    candidates = DECODER_CANDIDATES.get(suffix)
    if candidates is None:
        supported = ", ".join(sorted(DECODER_CANDIDATES))
        raise DecoderJobError(
            f"unsupported configuration extension {suffix!r}; supported: {supported}"
        )

    for candidate in candidates:
        path = root / candidate
        if path.is_file():
            return path

    names = ", ".join(candidates)
    raise DecoderJobError(
        f"decoder for {suffix} is not present in this checkout "
        f"(looked for: {names})"
    )


def _command_for(
    decoder: Path, suffix: str, input_path: Path, output_dir: Path
) -> tuple[list[str], Path]:
    output_path = output_dir / "decoded.txt"
    command = [sys.executable, str(decoder), str(input_path)]

    if suffix == ".tnl":
        xml_path = output_dir / "decoded.xml"
        json_path = output_dir / "decoded.json"
        command += ["--output", str(xml_path), "--json", str(json_path)]
        return command, json_path

    command += ["--output", str(output_path)]
    if suffix == ".dark":
        command += ["--keep-passwords", "--json-only"]
    elif suffix == ".nm":
        command += ["--pretty"]

    return command, output_path


def run_decoder(root: Path, input_path: Path, output_dir: Path) -> Path:
    suffix = input_path.suffix.lower()
    decoder = _find_decoder(root, suffix)
    output_dir.mkdir(parents=True, exist_ok=True)
    command, expected_output = _command_for(decoder, suffix, input_path, output_dir)

    completed = subprocess.run(
        command,
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        # Deliberately omit decoder stdout/stderr: it can contain profile data.
        raise DecoderJobError(
            f"{decoder.name} failed with exit code {completed.returncode}"
        )
    if not expected_output.is_file():
        raise DecoderJobError(
            f"{decoder.name} completed without producing its expected output"
        )

    result_path = output_dir / "result.txt"
    shutil.copyfile(expected_output, result_path)
    if result_path.stat().st_size == 0:
        raise DecoderJobError(f"{decoder.name} produced an empty result")
    return result_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path.cwd())
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)

    try:
        result = run_decoder(args.root.resolve(), args.input.resolve(), args.output_dir.resolve())
    except (OSError, DecoderJobError) as exc:
        print(f"decoder job failed: {exc}", file=sys.stderr)
        return 1

    print(f"decoder completed; result_bytes={result.stat().st_size}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())