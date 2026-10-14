Updated 2026-10-14

DarkTunnel: corrected URL-safe Base64 and AES-CFB outer and nested decryption.
NPVS v5: corrected metadata associated-data boundary to exclude the four-byte ciphertext length.
TLS: reverse Base64 text before decoding, matching Android.
Synthetic NPVS and TLS fixtures updated to match the recovered Android implementation.

Successful real-file checks: supplied .nm, .dark, .npvs, .sks, .hat and .tls exports. All 20 existing test groups pass. VPN connectivity was not tested. Compatibility with every exporter variant is not certified.
