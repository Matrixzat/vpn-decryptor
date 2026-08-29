#!/usr/bin/env python3
"""Decode SocksHTTP ``.sks`` files using the APK-verified key families.

The supported container is a small JSON object:

    {"v": <version>, "d": "<Base64(ciphertext)>.<Base64(iv)>"}

Known SocksHTTP generations derive an ASCII AES-256 key from version-specific
seeds, then decrypt the first segment with AES-CBC and PKCS#5/#7-compatible
padding. The decoder tries the key families recovered from the APK so future
versions that retain this same container and derivation remain compatible.

The module-level ``run(file_bytes)`` function is compatible with the central
decoder job.  It returns formatted JSON on success and ``None`` on invalid
input so a failed automated job never prints profile data.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - exercised by the CLI error path
    AES = None


class SocksHttpDecodeError(ValueError):
    """Raised when input is not a supported SocksHTTP profile."""


class SocksHttpDecoder:
    """Decoder for SocksHTTP's verified AES-CBC profile generations."""

    MODERN_KEY_SEED_PREFIX = "162exe235948e37ws6d057d9d85324e2 "
    LEGACY_KEY_SEED_PREFIX = "962exe865948e37ws6d057d4d85604e0 "
    LEGACY_PRE_V5_KEY = b"662ede816988e58fb6d057d9d85605e0"
    LEGACY_V5_KEY = b"962exe865948e37ws6d057d4d85604e0"
    BLOCK_SIZE = AES.block_size if AES is not None else 16

    @classmethod
    def _require_dependency(cls) -> None:
        if AES is None:
            raise SocksHttpDecodeError(
                "Missing dependency pycryptodome. Install with: "
                "python -m pip install pycryptodome"
            )

    @staticmethod
    def _decode_base64(value: Any, label: str) -> bytes:
        if not isinstance(value, str) or not value:
            raise SocksHttpDecodeError(f"SocksHTTP {label} is empty or not text.")

        try:
            # The APK uses Android Base64.NO_WRAP, which is standard Base64.
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise SocksHttpDecodeError(
                f"SocksHTTP {label} is not valid Base64."
            ) from exc

    @classmethod
    def _parse_container(cls, file_bytes: bytes) -> Tuple[int, bytes, bytes]:
        try:
            text = file_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SocksHttpDecodeError(
                "SocksHTTP input is not valid UTF-8 JSON."
            ) from exc

        try:
            container = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SocksHttpDecodeError(
                "SocksHTTP input is not valid JSON."
            ) from exc

        if not isinstance(container, dict):
            raise SocksHttpDecodeError("SocksHTTP container must be a JSON object.")

        version = container.get("v")
        if isinstance(version, bool) or not isinstance(version, int):
            raise SocksHttpDecodeError("SocksHTTP container has an invalid version.")
        if version < 0:
            raise SocksHttpDecodeError(
                f"SocksHTTP version must not be negative: {version}."
            )

        encoded = container.get("d")
        if not isinstance(encoded, str):
            raise SocksHttpDecodeError("SocksHTTP container is missing string field 'd'.")

        parts = encoded.split(".")
        if len(parts) != 2:
            raise SocksHttpDecodeError(
                "Malformed SocksHTTP data: expected ciphertext.iv."
            )

        ciphertext = cls._decode_base64(parts[0], "ciphertext")
        iv = cls._decode_base64(parts[1], "IV")
        if not ciphertext:
            raise SocksHttpDecodeError("SocksHTTP ciphertext is empty.")
        if len(iv) != cls.BLOCK_SIZE:
            raise SocksHttpDecodeError(
                f"SocksHTTP IV must be {cls.BLOCK_SIZE} bytes, got {len(iv)}."
            )
        if len(ciphertext) % cls.BLOCK_SIZE:
            raise SocksHttpDecodeError(
                "SocksHTTP ciphertext is not aligned to the AES block size."
            )

        return version, ciphertext, iv

    @classmethod
    def _versioned_key(cls, prefix: str, version: int) -> bytes:
        seed = f"{prefix}{version}".encode("ascii")
        # The APK converts MD5 to lowercase hexadecimal text, left-padding to
        # 32 characters, and uses those 32 ASCII bytes as the AES-256 key.
        return hashlib.md5(seed).hexdigest().rjust(32, "0").encode("ascii")

    @classmethod
    def _key_candidates(cls, version: int) -> List[Tuple[str, bytes]]:
        """Return the APK-known key generations in the safest order."""
        candidates: List[Tuple[str, bytes]] = []
        if version < 5:
            candidates.append(("legacy pre-v5", cls.LEGACY_PRE_V5_KEY))
        elif version == 5:
            candidates.append(("legacy v5", cls.LEGACY_V5_KEY))

        # Version 13 is a real modern-format sample, so prefer this family for
        # versioned profiles while retaining the older family as a fallback.
        candidates.extend(
            (
                (
                    "modern versioned",
                    cls._versioned_key(cls.MODERN_KEY_SEED_PREFIX, version),
                ),
                (
                    "legacy versioned",
                    cls._versioned_key(cls.LEGACY_KEY_SEED_PREFIX, version),
                ),
            )
        )
        return candidates

    @classmethod
    def _remove_padding(cls, plaintext: bytes) -> bytes:
        if not plaintext:
            raise SocksHttpDecodeError("SocksHTTP plaintext is empty.")

        padding_size = plaintext[-1]
        if not 1 <= padding_size <= cls.BLOCK_SIZE:
            raise SocksHttpDecodeError("SocksHTTP plaintext has invalid padding.")
        if plaintext[-padding_size:] != bytes([padding_size]) * padding_size:
            raise SocksHttpDecodeError("SocksHTTP plaintext has invalid padding.")
        return plaintext[:-padding_size]

    @classmethod
    def _decrypt_candidates(
        cls, version: int, ciphertext: bytes, iv: bytes
    ) -> List[Tuple[str, bytes]]:
        """Return candidates with valid padding and UTF-8, without exposing data."""
        candidates: List[Tuple[str, bytes]] = []
        for name, key in cls._key_candidates(version):
            try:
                decrypted = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ciphertext)
                plaintext = cls._remove_padding(decrypted)
                plaintext.decode("utf-8")
            except (SocksHttpDecodeError, UnicodeDecodeError, TypeError, ValueError):
                continue
            candidates.append((name, plaintext))
        return candidates

    @classmethod
    def decode_bytes(cls, file_bytes: bytes) -> bytes:
        """Decrypt a profile and return its unpadded UTF-8 JSON bytes."""
        cls._require_dependency()
        version, ciphertext, iv = cls._parse_container(file_bytes)
        candidates = cls._decrypt_candidates(version, ciphertext, iv)
        if not candidates:
            raise SocksHttpDecodeError(
                "SocksHTTP decryption failed for all known key generations."
            )
        return candidates[0][1]

    @classmethod
    def decode_json(cls, file_bytes: bytes) -> Dict[str, Any]:
        """Decrypt a profile and parse its JSON payload."""
        cls._require_dependency()
        version, ciphertext, iv = cls._parse_container(file_bytes)
        for _, plaintext in cls._decrypt_candidates(version, ciphertext, iv):
            try:
                payload = json.loads(plaintext.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
        raise SocksHttpDecodeError(
            "SocksHTTP decryption did not produce a valid JSON object."
        )

    @classmethod
    def run(cls, file_bytes: bytes) -> Optional[str]:
        """Return readable JSON or ``None`` when the input cannot be decoded."""
        try:
            payload = cls.decode_json(file_bytes)
        except Exception:
            return None
        return json.dumps(payload, indent=4, ensure_ascii=False)


def run(file_bytes: bytes) -> Optional[str]:
    """Module-level entry point used by ``scripts/decoder_job.py``."""
    return SocksHttpDecoder.run(file_bytes)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode a SocksHTTP .sks file using known key generations."
    )
    parser.add_argument("input", type=Path, help="Input .sks file")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Write decoded JSON to this file instead of stdout",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print the decoded JSON (the default output is also readable)",
    )
    args = parser.parse_args(argv)

    try:
        payload = SocksHttpDecoder.decode_json(args.input.read_bytes())
        output = json.dumps(
            payload if args.pretty else payload,
            indent=4 if args.pretty else None,
            ensure_ascii=False,
        )
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    except (OSError, SocksHttpDecodeError) as exc:
        print(f"Decode failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())