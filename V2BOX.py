#!/usr/bin/env python3
"""Decode V2Box version-1 ``.v2box`` exports.

V2Box stores an export as a JSON envelope containing Base64 AES-GCM fields.
The decrypted payload is JSON and contains the complete profile list plus the
raw configuration map, so all supported V2Box profile protocols are preserved.

Password-protected exports derive the AES-256 key as SHA-256(UTF-8 password).
Unprotected exports use the application export key recovered from V2Box's
import implementation. The module-level ``run(file_bytes)`` function is
compatible with ``scripts/decoder_job.py`` and decodes unprotected exports.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import getpass
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    from Crypto.Cipher import AES
except ImportError:  # pragma: no cover - exercised by the CLI error path
    AES = None


class V2BoxDecodeError(ValueError):
    """Raised when input is not a valid or decryptable V2Box export."""


class V2BoxPasswordRequired(V2BoxDecodeError):
    """Raised when a password-protected export has no supplied password."""


class V2BoxDecoder:
    """Decoder for V2Box's authenticated JSON export container."""

    MAGIC = "v2box_export"
    GCM_NONCE_SIZE = 12
    GCM_TAG_SIZE = 16
    # V2Box stores this as an obfuscated byte array in its import code.
    _UNPROTECTED_KEY_BYTES = (
        12,
        104,
        24,
        53,
        34,
        31,
        52,
        57,
        40,
        35,
        42,
        46,
        51,
        53,
        52,
        17,
        63,
        35,
        104,
        106,
        104,
        108,
        5,
        9,
        63,
        57,
        40,
        63,
        46,
        123,
        121,
        127,
    )
    UNPROTECTED_KEY = bytes(
        value ^ 0x5A for value in _UNPROTECTED_KEY_BYTES
    )

    @classmethod
    def _require_dependency(cls) -> None:
        if AES is None:
            raise V2BoxDecodeError(
                "Missing dependency pycryptodome. Install with: "
                "python -m pip install pycryptodome"
            )

    @staticmethod
    def _decode_base64(value: Any, label: str) -> bytes:
        if not isinstance(value, str) or not value:
            raise V2BoxDecodeError(f"V2Box {label} is empty or not text.")
        try:
            return base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise V2BoxDecodeError(f"V2Box {label} is not valid Base64.") from exc

    @classmethod
    def _parse_container(cls, file_bytes: bytes) -> Dict[str, Any]:
        try:
            text = file_bytes.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise V2BoxDecodeError("V2Box input is not valid UTF-8 JSON.") from exc

        try:
            container = json.loads(text)
        except json.JSONDecodeError as exc:
            raise V2BoxDecodeError("V2Box input is not valid JSON.") from exc

        if not isinstance(container, dict):
            raise V2BoxDecodeError("V2Box container must be a JSON object.")
        if container.get("magic") != cls.MAGIC:
            raise V2BoxDecodeError("V2Box magic signature mismatch.")

        version = container.get("version")
        if isinstance(version, bool) or not isinstance(version, int):
            raise V2BoxDecodeError("V2Box container has an invalid version.")
        if version != 1:
            raise V2BoxDecodeError(
                f"Unsupported V2Box export version: {version}; expected version 1."
            )

        protected = container.get("isPasswordProtected", False)
        if not isinstance(protected, bool):
            raise V2BoxDecodeError(
                "V2Box container has an invalid password-protection flag."
            )

        nonce = cls._decode_base64(container.get("nonce"), "nonce")
        ciphertext = cls._decode_base64(container.get("ciphertext"), "ciphertext")
        tag = cls._decode_base64(container.get("tag"), "authentication tag")

        if len(nonce) != cls.GCM_NONCE_SIZE:
            raise V2BoxDecodeError(
                f"V2Box nonce must be {cls.GCM_NONCE_SIZE} bytes, got {len(nonce)}."
            )
        if not ciphertext:
            raise V2BoxDecodeError("V2Box ciphertext is empty.")
        if len(tag) != cls.GCM_TAG_SIZE:
            raise V2BoxDecodeError(
                f"V2Box authentication tag must be {cls.GCM_TAG_SIZE} bytes, "
                f"got {len(tag)}."
            )

        return {
            "version": version,
            "isPasswordProtected": protected,
            "nonce": nonce,
            "ciphertext": ciphertext,
            "tag": tag,
        }

    @classmethod
    def _key_for(cls, protected: bool, password: Optional[str]) -> bytes:
        if not protected:
            return cls.UNPROTECTED_KEY
        if password is None or password == "":
            raise V2BoxPasswordRequired(
                "V2Box export is password-protected; supply a password."
            )
        return hashlib.sha256(password.encode("utf-8")).digest()

    @classmethod
    def decode_bytes(
        cls, file_bytes: bytes, password: Optional[str] = None
    ) -> bytes:
        """Decrypt an export and return its UTF-8 JSON payload."""
        cls._require_dependency()
        container = cls._parse_container(file_bytes)
        key = cls._key_for(container["isPasswordProtected"], password)

        try:
            cipher = AES.new(
                key,
                AES.MODE_GCM,
                nonce=container["nonce"],
                mac_len=cls.GCM_TAG_SIZE,
            )
            plaintext = cipher.decrypt_and_verify(
                container["ciphertext"], container["tag"]
            )
        except (ValueError, TypeError) as exc:
            if container["isPasswordProtected"]:
                raise V2BoxDecodeError("Incorrect password or corrupt V2Box export.") from exc
            raise V2BoxDecodeError("V2Box decryption failed or export is corrupt.") from exc

        try:
            plaintext.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise V2BoxDecodeError("V2Box plaintext is not valid UTF-8.") from exc
        return plaintext

    @classmethod
    def decode_json(
        cls, file_bytes: bytes, password: Optional[str] = None
    ) -> Dict[str, Any]:
        """Decrypt an export and parse its complete JSON payload."""
        plaintext = cls.decode_bytes(file_bytes, password=password)
        try:
            payload = json.loads(plaintext)
        except json.JSONDecodeError as exc:
            raise V2BoxDecodeError("V2Box decrypted payload is not valid JSON.") from exc
        if not isinstance(payload, dict):
            raise V2BoxDecodeError("V2Box decrypted payload must be a JSON object.")
        return payload

    @classmethod
    def run(
        cls, file_bytes: bytes, password: Optional[str] = None
    ) -> Optional[str]:
        """Return readable JSON, or ``None`` when automated decoding fails."""
        try:
            payload = cls.decode_json(file_bytes, password=password)
        except Exception:
            return None
        return json.dumps(payload, indent=4, ensure_ascii=False)


def run(file_bytes: bytes) -> Optional[str]:
    """Module-level entry point used by ``scripts/decoder_job.py``."""
    return V2BoxDecoder.run(file_bytes)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Decode an encrypted V2Box .v2box export."
    )
    parser.add_argument("input", type=Path, help="Input .v2box file")
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
        file_bytes = args.input.read_bytes()
        container = V2BoxDecoder._parse_container(file_bytes)
        password = None
        if container["isPasswordProtected"]:
            password = getpass.getpass("V2Box export password: ")
        payload = V2BoxDecoder.decode_json(file_bytes, password=password)
        output = json.dumps(
            payload,
            indent=4 if args.pretty else None,
            ensure_ascii=False,
        )
        if args.output:
            args.output.write_text(output + "\n", encoding="utf-8")
        else:
            print(output)
        return 0
    except (OSError, V2BoxDecodeError, ValueError) as exc:
        print(f"Decode failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())