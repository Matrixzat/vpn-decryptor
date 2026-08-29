import base64
import hashlib
import json
import sys
import unittest
from pathlib import Path

from Crypto.Cipher import AES

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import SOCKSHTTP


class SocksHttpDecoderTests(unittest.TestCase):
    @staticmethod
    def _fixture() -> bytes:
        plaintext = b'{"fixture":"sks-v20","enabled":true,"count":42}'
        pad_size = 16 - (len(plaintext) % 16)
        padded = plaintext + bytes([pad_size]) * pad_size
        seed = b"162exe235948e37ws6d057d9d85324e2 20"
        key = hashlib.md5(seed).hexdigest().encode("ascii")
        iv = bytes.fromhex("00112233445566778899aabbccddeeff")
        ciphertext = AES.new(key, AES.MODE_CBC, iv=iv).encrypt(padded)
        container = {
            "v": 20,
            "d": ".".join(
                (
                    base64.b64encode(ciphertext).decode("ascii"),
                    base64.b64encode(iv).decode("ascii"),
                )
            ),
        }
        return json.dumps(container).encode("utf-8")

    def test_decodes_version_20_fixture(self) -> None:
        payload = SOCKSHTTP.SocksHttpDecoder.decode_json(self._fixture())
        self.assertEqual(payload, {"fixture": "sks-v20", "enabled": True, "count": 42})

    def test_rejects_unsupported_version(self) -> None:
        container = json.loads(self._fixture())
        container["v"] = 19
        with self.assertRaises(SOCKSHTTP.SocksHttpDecodeError):
            SOCKSHTTP.SocksHttpDecoder.decode_json(json.dumps(container).encode())

    def test_rejects_malformed_segment_count(self) -> None:
        container = json.loads(self._fixture())
        container["d"] = container["d"].replace(".", "..", 1)
        with self.assertRaises(SOCKSHTTP.SocksHttpDecodeError):
            SOCKSHTTP.SocksHttpDecoder.decode_json(json.dumps(container).encode())

    def test_uploaded_sample_has_expected_structure_when_present(self) -> None:
        sample = Path(__file__).resolve().parents[1] / (
            "attached_assets/magic_1787965557664.sks"
        )
        if not sample.is_file():
            self.skipTest("uploaded sample is not present in this checkout")

        payload = SOCKSHTTP.SocksHttpDecoder.decode_json(sample.read_bytes())
        self.assertIsInstance(payload.get("sshServer"), str)
        self.assertIsInstance(payload.get("dnsCustom"), list)
        self.assertIsInstance(payload.get("profileSshAuth"), dict)
        self.assertIsInstance(payload.get("configProtect"), dict)


if __name__ == "__main__":
    unittest.main()