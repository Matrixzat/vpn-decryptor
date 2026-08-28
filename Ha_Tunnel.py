#!/usr/bin/env python3
"""HAT Tunnel configuration decoder."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


# HAT Tunnel's fixed AES-128-ECB configuration key.
_HAT_KEY = base64.b64decode("zbNkuNCGSLivpEuep3BcNA==")


class HatDecodeError(ValueError):
    """Raised when a HAT file is invalid or cannot be decrypted."""


def decrypt_hat(file_bytes: bytes) -> str:
    """Decrypt a HAT file and return its UTF-8 configuration text."""
    encoded = b"".join(file_bytes.split())
    if not encoded:
        raise HatDecodeError("input file is empty")

    try:
        encrypted = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HatDecodeError("input is not valid Base64") from exc

    if not encrypted or len(encrypted) % AES.block_size:
        raise HatDecodeError("decoded HAT payload is not AES block aligned")

    try:
        decrypted = AES.new(_HAT_KEY, AES.MODE_ECB).decrypt(encrypted)
        plaintext = unpad(decrypted, AES.block_size)
    except ValueError as exc:
        raise HatDecodeError("HAT decryption or padding validation failed") from exc

    try:
        return plaintext.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HatDecodeError("decrypted HAT content is not UTF-8") from exc


def format_output(text: str) -> str:
    """Make JSON-based profiles readable while preserving non-JSON text."""
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return text if text.endswith("\n") else text + "\n"
    return json.dumps(value, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="Ha_Tunnel.py",
        description="Decrypt a HAT Tunnel configuration.",
    )
    parser.add_argument("input", type=Path, help="input .hat file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output text path (default: INPUT.decrypted.txt)",
    )
    args = parser.parse_args(argv)
    output = args.output or args.input.with_suffix(".decrypted.txt")

    try:
        result = format_output(decrypt_hat(args.input.read_bytes()))
        output.write_text(result, encoding="utf-8")
    except (OSError, HatDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"HAT configuration written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())