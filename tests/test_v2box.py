import base64
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

from Crypto.Cipher import AES

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import V2BOX
from scripts.decoder_job import DecoderJobError, run_decoder


class V2BoxDecoderTests(unittest.TestCase):
    KNOWN_PAYLOAD = {
        "configs": [{"configType": "VLESS", "id": "fixture-vless"}],
        "raws": {"fixture-vless": "vless fixture only"},
    }
    KNOWN_VECTOR = (
        b'{"magic":"v2box_export","version":1,"isPasswordProtected":false,'
        b'"nonce":"AAECAwQFBgcICQoL","ciphertext":"qQlEaqquAbeytaDoeKYc8TRK'
        b'Xqh9evQgtwb7NVL/33UDtq1GA6uBnTdDqz7SgCX4lV3ZeKTcQPxE/XGRjFqC'
        b'xcdwKKcXP1P4jKOMj0Qgb59giuI38alce1L/+rjxgPJ8CSLfSrvf3g==",'
        b'"tag":"vToEYzPIWrxXYlU5M9kZZQ=="}'
    )

    @staticmethod
    def _fixture(password=None, protocols=None) -> bytes:
        protocols = protocols or ("VLESS", "VMESS", "TROJAN", "SHADOWSOCKS")
        configs = [
            {"id": f"fixture-{index}", "configType": protocol}
            for index, protocol in enumerate(protocols)
        ]
        payload = {
            "a": {"fixture": True},
            "b": ["metadata"],
            "configs": configs,
            "raws": {
                config["id"]: f"{config['configType']} fixture data"
                for config in configs
            },
        }
        plaintext = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        nonce = bytes.fromhex("00112233445566778899aabb")
        if password is None:
            key = V2BOX.V2BoxDecoder.UNPROTECTED_KEY
            protected = False
        else:
            key = hashlib.sha256(password.encode("utf-8")).digest()
            protected = True

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return json.dumps(
            {
                "magic": "v2box_export",
                "version": 1,
                "isPasswordProtected": protected,
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
                "tag": base64.b64encode(tag).decode("ascii"),
            }
        ).encode("utf-8")

    def test_decodes_unprotected_multi_protocol_export(self) -> None:
        protocols = ("VLESS", "VMESS", "TROJAN", "SHADOWSOCKS", "SSH", "HYSTERIA2")
        payload = V2BOX.V2BoxDecoder.decode_json(self._fixture(protocols=protocols))
        self.assertEqual(
            [config["configType"] for config in payload["configs"]],
            list(protocols),
        )
        self.assertEqual(len(payload["raws"]), len(protocols))

    def test_decodes_independent_known_vector(self) -> None:
        payload = V2BOX.V2BoxDecoder.decode_json(self.KNOWN_VECTOR)
        self.assertEqual(payload, self.KNOWN_PAYLOAD)

    def test_decodes_password_protected_export(self) -> None:
        payload = V2BOX.V2BoxDecoder.decode_json(
            self._fixture(password="correct horse battery staple"),
            password="correct horse battery staple",
        )
        self.assertTrue(payload["a"]["fixture"])

    def test_requires_password_for_protected_export(self) -> None:
        with self.assertRaises(V2BOX.V2BoxPasswordRequired):
            V2BOX.V2BoxDecoder.decode_json(self._fixture(password="secret"))

    def test_rejects_wrong_password(self) -> None:
        with self.assertRaises(V2BOX.V2BoxDecodeError):
            V2BOX.V2BoxDecoder.decode_json(
                self._fixture(password="secret"),
                password="wrong",
            )

    def test_rejects_magic_mismatch(self) -> None:
        container = json.loads(self._fixture())
        container["magic"] = "not_v2box"
        with self.assertRaises(V2BOX.V2BoxDecodeError):
            V2BOX.V2BoxDecoder.decode_json(json.dumps(container).encode("utf-8"))

    def test_rejects_unsupported_version(self) -> None:
        container = json.loads(self._fixture())
        container["version"] = 2
        with self.assertRaises(V2BOX.V2BoxDecodeError):
            V2BOX.V2BoxDecoder.decode_json(json.dumps(container).encode("utf-8"))

    def test_decoder_job_routes_v2box(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "fixture.v2box"
            input_path.write_bytes(self.KNOWN_VECTOR)
            result = run_decoder(root, input_path, temp_path / "output")
            self.assertEqual(json.loads(result.read_text()), self.KNOWN_PAYLOAD)

    def test_decoder_job_routes_v2ray_alias(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "ghaha.v2ray"
            input_path.write_bytes(self.KNOWN_VECTOR)
            result = run_decoder(root, input_path, temp_path / "output")
            self.assertEqual(json.loads(result.read_text()), self.KNOWN_PAYLOAD)

    def test_decoder_job_rejects_protected_export_without_password(self) -> None:
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            input_path = temp_path / "protected.v2box"
            input_path.write_bytes(self._fixture(password="secret"))
            with self.assertRaises(DecoderJobError):
                run_decoder(root, input_path, temp_path / "output")

    def test_uploaded_sample_when_present(self) -> None:
        sample = Path(__file__).resolve().parents[1] / (
            "attached_assets/سوا_مجانا_1787971039031.v2box"
        )
        if not sample.is_file():
            self.skipTest("uploaded V2Box sample is not present in this checkout")

        payload = V2BOX.V2BoxDecoder.decode_json(sample.read_bytes())
        self.assertIsInstance(payload.get("configs"), list)
        self.assertEqual(len(payload["configs"]), 1)
        self.assertIsInstance(payload.get("raws"), dict)


if __name__ == "__main__":
    unittest.main()