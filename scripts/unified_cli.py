"""Local CLI and byte API shared by the familiar decoder entry points."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tempfile
import json
import xml.etree.ElementTree as ET

from .decoder_job import DecoderJobError, run_decoder
from .ported_engine import ROOT, formats, infer_suffix


def run_bytes(data: bytes, suffix: str, *, password: str | None = None,
              hwid: str | None = None) -> str:
    if not isinstance(data, bytes):
        raise DecoderJobError("The decoder expects bytes")
    with tempfile.TemporaryDirectory(prefix="vpn-decoder-") as temp:
        folder = Path(temp)
        input_path = folder / "input.bin"
        input_path.write_bytes(data)
        result = run_decoder(ROOT, input_path, folder / "output", suffix=suffix,
                             password=password, hwid=hwid)
        return result.read_text(encoding="utf-8")


def main(argv: list[str] | None = None, *, default_suffix: str | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unified VPN decoder: SP-DECODE with merged exporter variants")
    parser.add_argument("input", nargs="?", type=Path)
    parser.add_argument("legacy_output", nargs="?", type=Path,
                        help="Optional positional output path for existing SocksIP usage")
    parser.add_argument("-o", "--output", type=Path)
    parser.add_argument("--json", dest="json_output", type=Path,
                        help="Additional JSON output (compatible with OpenTunnel's former CLI)")
    parser.add_argument("--suffix")
    parser.add_argument("--password")
    parser.add_argument("--hwid")
    parser.add_argument("--list", action="store_true")
    args = parser.parse_args(argv)
    if args.list:
        print("\n".join("." + suffix for suffix in sorted(formats())))
        return 0
    if args.input is None:
        parser.error("input is required unless --list is used")
    inferred = infer_suffix(args.input.name)
    suffix = args.suffix or (inferred if inferred in formats() else default_suffix)
    if not suffix:
        parser.error("Could not infer a supported format; use --suffix")
    try:
        with tempfile.TemporaryDirectory(prefix="vpn-decoder-") as temp:
            result = run_decoder(ROOT, args.input.resolve(), Path(temp), suffix=suffix,
                                 password=args.password, hwid=args.hwid)
            text = result.read_text(encoding="utf-8")
            output = args.output or args.legacy_output
            if args.json_output:
                args.json_output.write_text(text, encoding="utf-8")
            if output:
                if output.suffix.lower()==".xml" and suffix.lstrip(".").lower()=="tnl":
                    config=json.loads(text)
                    if not isinstance(config,dict):
                        raise DecoderJobError("OpenTunnel XML output requires a properties object")
                    properties=ET.Element("properties")
                    for key,value in config.items():
                        ET.SubElement(properties,"entry",key=str(key)).text=str(value)
                    output.write_bytes(ET.tostring(properties,encoding="utf-8",xml_declaration=True))
                else:
                    output.write_text(text, encoding="utf-8")
            else:
                sys.stdout.write(text)
        return 0
    except (OSError, DecoderJobError) as error:
        print(f"Decode failed: {error}", file=sys.stderr)
        return 1
