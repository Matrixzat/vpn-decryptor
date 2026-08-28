#!/usr/bin/env python3
"""Run one checked-in configuration decoder without exposing plaintext in logs."""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
from types import ModuleType
from pathlib import Path


DECODER_CANDIDATES: dict[str, tuple[str, ...]] = {
    ".ehi": ("HTTPINJECTOR.py", "HttpInjector.py", "httpinjector.py", "ehi_decoder.py"),
    ".npvt": ("NPVTUNNEL.py", "NPVTunnel.py", "npvtunnel.py", "npvt_decoder.py"),
    ".hc": ("HTTPCUSTOM.py", "HTTP_Custom.py", "http_custom.py", "httpcustom_decoder.py"),
    ".dark": ("DARKTUNNEL.py", "darktunnel_decoder.py"),
    ".nm": ("NETMOD.py", "netmod_decoder.py"),
    ".sip": ("SocksIP.py", "socksip.py"),
    ".tnl": ("OPENTUNNEL_TNL.py", "tnl_decoder.py"),
    ".ziv": ("ZIVPN.py", "zivpn.py"),
    ".hat": ("Ha_Tunnel.py", "ha_tunnel.py"),
    ".ssc": ("SSCCUSTOM.py",),
}

PROGRAMMATIC_SUFFIXES = {".ehi", ".npvt", ".hc", ".dark", ".nm", ".ziv", ".ssc"}


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

    if suffix == ".sip":
        command.append(str(output_path))
    else:
        command += ["--output", str(output_path)]

    return command, output_path


def _load_decoder_module(decoder: Path) -> ModuleType:
    module_name = f"_decoder_{decoder.stem.lower()}"
    spec = importlib.util.spec_from_file_location(module_name, decoder)
    if spec is None or spec.loader is None:
        raise DecoderJobError(f"could not load {decoder.name}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_programmatic_decoder(
    decoder: Path, input_path: Path, output_dir: Path
) -> Path:
    module = _load_decoder_module(decoder)
    decode = getattr(module, "run", None)
    if not callable(decode):
        raise DecoderJobError(f"{decoder.name} does not expose run(file_bytes)")

    result = decode(input_path.read_bytes())
    if result is None:
        raise DecoderJobError(f"{decoder.name} could not decode the input")
    if isinstance(result, bytes):
        try:
            text = result.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise DecoderJobError(
                f"{decoder.name} produced non-UTF-8 output"
            ) from exc
    elif isinstance(result, str):
        text = result
    else:
        raise DecoderJobError(
            f"{decoder.name} returned unsupported output type "
            f"{type(result).__name__}"
        )

    output_path = output_dir / "decoded.txt"
    output_path.write_text(text, encoding="utf-8")
    return output_path


def run_decoder(root: Path, input_path: Path, output_dir: Path) -> Path:
    suffix = input_path.suffix.lower()
    decoder = _find_decoder(root, suffix)
    output_dir.mkdir(parents=True, exist_ok=True)
    if suffix in PROGRAMMATIC_SUFFIXES:
        expected_output = _run_programmatic_decoder(decoder, input_path, output_dir)
    else:
        command, expected_output = _command_for(
            decoder, suffix, input_path, output_dir
        )
        completed = subprocess.run(
            command,
            cwd=root,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            # Deliberately omit decoder output: it can contain profile data.
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