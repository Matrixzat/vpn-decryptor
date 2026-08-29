import base64
import json
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import NETMOD
from scripts.decoder_job import run_decoder


class NetModDecoderTests(unittest.TestCase):
    PAYLOAD = {
        "name": "fixture",
        "configType": "VLESS",
        "enabled": True,
    }

    @classmethod
    def _fixture(cls, key: bytes) -> bytes:
        plaintext = json.dumps(
            cls.PAYLOAD,
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(pad(plaintext, 16))
        return base64.b64encode(ciphertext)

    def test_decodes_all_known_key_families(self) -> None:
        for key in NETMOD.NetModDecoder.KEYS:
            with self.subTest(key_family=key):
                decoded = NETMOD.NetModDecoder.decode_json(self._fixture(key))
                self.assertEqual(decoded, self.PAYLOAD)

    def test_decoder_job_routes_newer_key_family(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "fixture.nm"
            input_path.write_bytes(
                self._fixture(NETMOD.NetModDecoder.KEYS[0])
            )
            result = run_decoder(root, input_path, temp_path / "output")
            self.assertEqual(json.loads(result.read_text()), self.PAYLOAD)

    def test_rejects_unknown_key(self) -> None:
        fixture = self._fixture(b"unknown-key-1234")
        with self.assertRaises(NETMOD.NetModDecodeError):
            NETMOD.NetModDecoder.decode_bytes(fixture)

    def test_uploaded_sample_when_present(self) -> None:
        samples = list(
            (Path(__file__).resolve().parents[1] / "attached_assets").glob(
                "STCFREE_VIP_*.nm"
            )
        )
        if not samples:
            self.skipTest("uploaded NetMod sample is not present")

        decoded = NETMOD.NetModDecoder.decode_json(samples[0].read_bytes())
        self.assertIsInstance(decoded, dict)


if __name__ == "__main__":
    unittest.main()