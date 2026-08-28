#!/usr/bin/env python3
"""Decrypt ZIVPN .ziv configuration files."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Tuple

from Crypto.Cipher import AES


PASSWORD = (
    b"SecurePart1SecurePart2SecurePart3"
    b"SecurePart4SecurePart5"
)
PBKDF2_ITERATIONS = 1_000
KEY_LENGTH = 16
NONCE_LENGTH = 12
TAG_LENGTH = 16


class ZivpnDecodeError(ValueError):
    """Base class for ZIVPN decoder errors."""


class ZivpnFormatError(ZivpnDecodeError):
    """Input is not a supported ZIVPN envelope."""


class ZivpnAuthenticationError(ZivpnDecodeError):
    """AES-GCM authentication failed."""


def _parse_xml(xml_bytes: bytes) -> Dict[str, str]:
    try:
        text = xml_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ZivpnDecodeError("decrypted configuration is not UTF-8") from exc

    # Java Properties.storeToXML can encode supplementary characters as
    # numeric UTF-16 surrogate pairs, which strict XML 1.0 parsers reject.
    def combine_surrogates(match: re.Match[str]) -> str:
        high_text = match.group(1) or match.group(2)
        low_text = match.group(3) or match.group(4)
        high = int(high_text, 16 if match.group(1) else 10)
        low = int(low_text, 16 if match.group(3) else 10)
        if 0xD800 <= high <= 0xDBFF and 0xDC00 <= low <= 0xDFFF:
            return chr(0x10000 + ((high - 0xD800) << 10) + low - 0xDC00)
        return match.group(0)

    text = re.sub(
        r"&#(?:x([0-9A-Fa-f]+)|([0-9]+));"
        r"&#(?:x([0-9A-Fa-f]+)|([0-9]+));",
        combine_surrogates,
        text,
    )

    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise ZivpnDecodeError(f"decrypted configuration is not valid XML: {exc}") from exc
    if root.tag != "properties":
        raise ZivpnDecodeError(f"unexpected XML root: {root.tag!r}")

    properties: Dict[str, str] = {}
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is None:
            raise ZivpnDecodeError("configuration entry has no key")
        properties[key] = entry.text or ""
    if not properties:
        raise ZivpnDecodeError("configuration contains no properties")
    return properties


def decrypt(file_bytes: bytes) -> Tuple[bytes, Dict[str, str]]:
    """Authenticate and decrypt a ZIVPN .ziv profile."""
    try:
        envelope = file_bytes.decode("ascii").strip()
    except UnicodeDecodeError as exc:
        raise ZivpnFormatError("ZIVPN input must be ASCII Base64 text") from exc

    parts = envelope.split(".")
    if len(parts) != 3:
        raise ZivpnFormatError(
            "expected three Base64 fields: salt.iv.ciphertext_and_tag"
        )
    try:
        salt, nonce, encrypted = (
            base64.b64decode(part, validate=True) for part in parts
        )
    except (binascii.Error, ValueError) as exc:
        raise ZivpnFormatError("invalid Base64 in ZIVPN envelope") from exc

    if len(salt) != 32:
        raise ZivpnFormatError(f"invalid salt length: expected 32, got {len(salt)}")
    if len(nonce) != NONCE_LENGTH:
        raise ZivpnFormatError(
            f"invalid nonce length: expected {NONCE_LENGTH}, got {len(nonce)}"
        )
    if len(encrypted) < TAG_LENGTH:
        raise ZivpnFormatError("encrypted data is shorter than its authentication tag")

    key = hashlib.pbkdf2_hmac(
        "sha256", PASSWORD, salt, PBKDF2_ITERATIONS, dklen=KEY_LENGTH
    )
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=TAG_LENGTH)
        plaintext = cipher.decrypt_and_verify(
            encrypted[:-TAG_LENGTH], encrypted[-TAG_LENGTH:]
        )
    except ValueError as exc:
        raise ZivpnAuthenticationError(
            "ZIVPN authentication failed; the file may be corrupt or unsupported"
        ) from exc
    return plaintext, _parse_xml(plaintext)


def format_text(properties: Dict[str, str]) -> str:
    lines = [
        "ZIVPN - decrypted configuration",
        "=" * 42,
        "",
        f"Recovered properties: {len(properties)}",
        "",
        "KEY = VALUE",
        "-" * 42,
    ]
    for key, value in properties.items():
        if "\n" in value:
            lines.append(f"{key} =")
            lines.extend(f"  {line}" for line in value.splitlines())
        else:
            lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def run(file_bytes: bytes) -> str:
    """Return a readable decrypted configuration."""
    _, properties = decrypt(file_bytes)
    return format_text(properties)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Decrypt a ZIVPN .ziv profile")
    parser.add_argument("input", type=Path, help="input .ziv file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="output text path (default: INPUT.decrypted.txt)",
    )
    args = parser.parse_args(argv)
    output = args.output or args.input.with_suffix(".decrypted.txt")

    try:
        output.write_text(run(args.input.read_bytes()), encoding="utf-8")
    except (OSError, ZivpnDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"Decrypted configuration written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())