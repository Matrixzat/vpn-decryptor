#!/usr/bin/env python3
"""Decode NetMod Syna .nm configuration files.

Format:
    Base64( AES-128-ECB( UTF-8 JSON + block padding ) )

The fixed NetMod Syna key is part of the public format implementation.

Dependencies:
    python -m pip install pycryptodome

Examples:
    python netmod_decoder.py profile.nm
    python netmod_decoder.py profile.nm --pretty -o decoded.json

The run(bytes) function returns the decrypted plaintext and is suitable for
use by a file-routing bot.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import re
import sys
from pathlib import Path
from typing import Any, List, Optional

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - exercised by the CLI error path
    AES = None


class NetModDecodeError(ValueError):
    """Raised when input is not a valid NetMod Syna profile."""


class NetModDecoder:
    """Decoder for the NetMod Syna Base64/AES-ECB profile format."""

    KEYS = (
        b"<n3t5yn4^n3tm0d>",
        b"_netsyna_netmod_",
        b"nicetrybuddygoon",
    )
    # Retained for callers that imported the original single-key constant.
    KEY = KEYS[1]
    BLOCK_SIZE = AES.block_size if AES is not None else 16

    @classmethod
    def _require_dependency(cls) -> None:
        if AES is None:
            raise NetModDecodeError(
                "Missing dependency pycryptodome. Install with: "
                "python -m pip install pycryptodome"
            )

    @staticmethod
    def _extract_payload(file_bytes: bytes) -> str:
        try:
            text = file_bytes.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise NetModDecodeError("NetMod input must be ASCII Base64 text.") from exc

        if not text:
            raise NetModDecodeError("NetMod input is empty.")

        # Also accept links such as nm-vless://<payload>.
        if "://" in text:
            text = text.split("://", 1)[1]

        # Newlines and spaces are harmless in Base64 input.
        return re.sub(r"\s+", "", text)

    @staticmethod
    def _decode_base64(payload: str) -> bytes:
        # NetMod uses standard Base64, while accepting URL-safe variants makes
        # the CLI more tolerant of links copied through chat applications.
        padded = payload + ("=" * ((4 - len(payload) % 4) % 4))
        try:
            return base64.b64decode(
                padded,
                altchars=b"-_",
                validate=True,
            )
        except (binascii.Error, ValueError) as exc:
            raise NetModDecodeError("Invalid NetMod Base64 payload.") from exc

    @classmethod
    def _remove_block_padding(cls, plaintext: bytes) -> bytes:
        if not plaintext:
            return plaintext

        # Current profiles use PKCS#7; older public implementations also
        # account for profiles padded with zero bytes.
        pad_size = plaintext[-1]
        if (
            1 <= pad_size <= cls.BLOCK_SIZE
            and plaintext.endswith(bytes([pad_size]) * pad_size)
        ):
            return plaintext[:-pad_size]
        return plaintext.rstrip(b"\x00")

    @classmethod
    def decode_bytes(cls, file_bytes: bytes) -> str:
        """Decrypt a .nm file and return its UTF-8 plaintext."""
        cls._require_dependency()
        payload = cls._extract_payload(file_bytes)
        ciphertext = cls._decode_base64(payload)

        if not ciphertext:
            raise NetModDecodeError("Decoded NetMod ciphertext is empty.")
        if len(ciphertext) % cls.BLOCK_SIZE:
            raise NetModDecodeError(
                "Ciphertext length is not aligned to the AES block size."
            )

        utf8_fallback = None
        for key in cls.KEYS:
            try:
                plaintext = AES.new(key, AES.MODE_ECB).decrypt(ciphertext)
            except Exception:
                continue

            plaintext = cls._remove_block_padding(plaintext)
            try:
                text = plaintext.decode("utf-8")
            except UnicodeDecodeError:
                continue

            try:
                json.loads(text)
            except json.JSONDecodeError:
                if utf8_fallback is None:
                    utf8_fallback = text
                continue
            return text

        if utf8_fallback is not None:
            return utf8_fallback
        raise NetModDecodeError(
            "No known NetMod key produced valid UTF-8 data."
        )

    @classmethod
    def decode_json(cls, file_bytes: bytes) -> Any:
        """Decrypt a .nm file and parse its plaintext as JSON."""
        plaintext = cls.decode_bytes(file_bytes)
        try:
            return json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise NetModDecodeError(
                "Decrypted NetMod plaintext is not valid JSON."
            ) from exc

    @classmethod
    def run(cls, file_bytes: bytes) -> Optional[str]:
        """Bot-compatible entry point; returns None if decoding fails."""
        try:
            return cls.decode_bytes(file_bytes)
        except Exception:
            return None


def run(file_bytes: bytes) -> Optional[str]:
    """Module-level entry point compatible with the other decoders."""
    return NetModDecoder.run(file_bytes)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode a NetMod Syna .nm file or nm-*:// link."
    )
    parser.add_argument("input", type=Path, help="Input .nm file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write the decrypted configuration to this file",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the decrypted JSON",
    )
    args = parser.parse_args(argv)

    try:
        plaintext = NetModDecoder.decode_bytes(args.input.read_bytes())
        if args.pretty:
            parsed = json.loads(plaintext)
            output = json.dumps(parsed, indent=2, ensure_ascii=False)
        else:
            output = plaintext

        if args.output:
            args.output.write_text(output, encoding="utf-8")
        else:
            print(output)
        return 0
    except (OSError, NetModDecodeError, ValueError) as exc:
        print(f"Decode failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())