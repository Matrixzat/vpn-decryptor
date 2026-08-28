#!/usr/bin/env python3
"""Decode OpenTunnel OPL v2 (.tnl) configuration files."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import struct
import sys
import xml.etree.ElementTree as ET
import zlib
from pathlib import Path

from Crypto.Cipher import AES


MAGIC = b"OPL\x02"
LENGTH_XOR = 0xA7B3C5D1
APP_SECRET = (
    b"f3a91c4e2d7b05869e4f1a3c8d2e6b07"
    b"a5c9f2e14d8b3a76e0f5c1d9b4a72e3f"
)
PBKDF2_ITERATIONS = 100_000
KEY_SIZE = 32
GCM_TAG_SIZE = 16
HEADER_SIZE = 12


class TnlDecodeError(ValueError):
    """Base class for deterministic decoder failures."""


class UnsupportedFormatError(TnlDecodeError):
    """The input is not an OpenTunnel OPL v2 container."""


class TruncatedFileError(TnlDecodeError):
    """The container ended before all declared bytes were available."""


class IntegrityError(TnlDecodeError):
    """The outer container checksum or length is invalid."""


class AuthenticationError(TnlDecodeError):
    """AES-GCM authentication failed."""


class PayloadError(TnlDecodeError):
    """The authenticated payload is not a valid OpenTunnel properties document."""


def _rotate_left_8(value: int, count: int) -> int:
    count &= 7
    if count == 0:
        return value & 0xFF
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _deobfuscate_body(body: bytes) -> bytes:
    return bytes(
        value ^ _rotate_left_8(0xC3, index) ^ (index & 0xFF)
        for index, value in enumerate(body)
    )


def unwrap_container(data: bytes) -> str:
    """Verify and unwrap an OPL v2 container into its dotted crypto envelope."""
    if len(data) < 4:
        raise TruncatedFileError("file is too short to contain an OPL header")
    if data[:3] != b"OPL":
        raise UnsupportedFormatError("not an OpenTunnel OPL container")
    if data[:4] != MAGIC:
        version = data[3]
        raise UnsupportedFormatError(f"unsupported OPL version: {version}")
    if len(data) < HEADER_SIZE:
        raise TruncatedFileError("OPL v2 header is truncated")

    encoded_length, expected_crc = struct.unpack_from("<II", data, 4)
    declared_length = encoded_length ^ LENGTH_XOR
    body = data[HEADER_SIZE:]
    if len(body) < declared_length:
        raise TruncatedFileError(
            f"payload is truncated: expected {declared_length} bytes, got {len(body)}"
        )
    if len(body) > declared_length:
        raise IntegrityError(
            f"unexpected trailing data: expected {declared_length} payload bytes, "
            f"got {len(body)}"
        )

    envelope = _deobfuscate_body(body)
    actual_crc = zlib.crc32(envelope) & 0xFFFFFFFF
    if actual_crc != expected_crc:
        raise IntegrityError(
            f"payload CRC32 mismatch: expected {expected_crc:08x}, got {actual_crc:08x}"
        )
    try:
        return envelope.decode("ascii")
    except UnicodeDecodeError as exc:
        raise PayloadError("crypto envelope is not ASCII") from exc


def decrypt_envelope(envelope: str, secret: bytes = APP_SECRET) -> bytes:
    """Authenticate and decrypt an OpenTunnel dotted AES-GCM envelope."""
    parts = envelope.split(".")
    if len(parts) != 3:
        raise PayloadError("crypto envelope must contain three Base64 fields")
    try:
        salt, nonce, ciphertext_and_tag = (
            base64.b64decode(part, validate=True) for part in parts
        )
    except (binascii.Error, ValueError) as exc:
        raise PayloadError("crypto envelope contains invalid Base64") from exc

    if len(salt) != KEY_SIZE:
        raise PayloadError(f"invalid salt length: expected 32, got {len(salt)}")
    if len(nonce) != 12:
        raise PayloadError(f"invalid AES-GCM nonce length: expected 12, got {len(nonce)}")
    if len(ciphertext_and_tag) < GCM_TAG_SIZE:
        raise PayloadError("AES-GCM ciphertext is shorter than its authentication tag")

    key = hashlib.pbkdf2_hmac(
        "sha256", secret, salt, PBKDF2_ITERATIONS, dklen=KEY_SIZE
    )
    ciphertext = ciphertext_and_tag[:-GCM_TAG_SIZE]
    tag = ciphertext_and_tag[-GCM_TAG_SIZE:]
    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=GCM_TAG_SIZE)
        return cipher.decrypt_and_verify(ciphertext, tag)
    except ValueError as exc:
        raise AuthenticationError(
            "AES-GCM authentication failed; the file is corrupt or the secret is wrong"
        ) from exc


def parse_properties_xml(xml_data: bytes) -> dict[str, str]:
    """Parse authenticated Java Properties XML without resolving its external DTD."""
    try:
        xml_text = xml_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PayloadError("decrypted XML is not valid UTF-8") from exc

    # Java Properties.storeToXML may serialize supplementary Unicode characters
    # as two numeric UTF-16 surrogate references. XML 1.0 parsers correctly
    # reject the individual surrogate code points, so combine each valid pair.
    def replace_surrogate_pair(match: re.Match[str]) -> str:
        high_text = match.group(1) or match.group(2)
        low_text = match.group(3) or match.group(4)
        high = int(high_text, 16 if match.group(1) else 10)
        low = int(low_text, 16 if match.group(3) else 10)
        if 0xD800 <= high <= 0xDBFF and 0xDC00 <= low <= 0xDFFF:
            return chr(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
        return match.group(0)

    xml_text = re.sub(
        r"&#(?:x([0-9A-Fa-f]+)|([0-9]+));&#(?:x([0-9A-Fa-f]+)|([0-9]+));",
        replace_surrogate_pair,
        xml_text,
    )
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise PayloadError(f"decrypted payload is not valid XML: {exc}") from exc
    if root.tag != "properties":
        raise PayloadError(f"unexpected XML root element: {root.tag!r}")

    properties: dict[str, str] = {}
    for entry in root.findall("entry"):
        key = entry.get("key")
        if key is None:
            raise PayloadError("properties XML contains an entry without a key")
        properties[key] = entry.text or ""
    if not properties:
        raise PayloadError("properties XML contains no configuration entries")
    return properties


def decode_tnl(data: bytes, secret: bytes = APP_SECRET) -> tuple[bytes, dict[str, str]]:
    envelope = unwrap_container(data)
    plaintext = decrypt_envelope(envelope, secret)
    return plaintext, parse_properties_xml(plaintext)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decrypt an OpenTunnel OPL v2 .tnl configuration"
    )
    parser.add_argument("input", type=Path, help="input .tnl file")
    parser.add_argument(
        "-o", "--output", type=Path, help="output XML path (default: INPUT.decrypted.xml)"
    )
    parser.add_argument(
        "--json", dest="json_output", type=Path, help="optional readable JSON output path"
    )
    args = parser.parse_args(argv)

    output = args.output or args.input.with_suffix(".decrypted.xml")
    try:
        plaintext, properties = decode_tnl(args.input.read_bytes())
        output.write_bytes(plaintext)
        if args.json_output:
            args.json_output.write_text(
                json.dumps(properties, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
    except (OSError, TnlDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    print(f"Decrypted {len(properties)} properties to {output}")
    if args.json_output:
        print(f"Wrote readable JSON to {args.json_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())