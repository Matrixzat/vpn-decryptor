# Complete SP-DECODE TLS-fixed import

## Source and preservation

- The uploaded ZIP is preserved separately in the workspace attachment directory.
- Its separate extracted source is `imports/spdecode-tls-fixed/spdecode_python/` at the workspace root.
- Its complete application copy is `vendor/spdecode_python/` in this repository, with documented variant merges.
- All **119 files / 1,215,168 bytes** were copied, including **77 decoder entry scripts**, shared engines, profiles, binary whitebox tables, indexes, documentation, and validation fixtures.
- Original reference tree SHA-256: `30678d95f4c70da16cc9a3d94c87e28f72fde325a12714b9a8712533524357c0`.
- All 119 upstream files remain present. 111 remain byte-identical; 8 contain intentional merges. Four focused engine modules were added.
- Original root-level implementations have been removed and replaced by thin entry points into the unified engine. Comparison-only originals are outside this repository at `imports/original-vpn-decryptor/`; they are not shipped or imported.

## Active routing

`decode.py`, every root decoder entry point, and `scripts/decoder_job.py` use only the unified SP-DECODE engine. The catalog contains 239 suffixes; the separately exposed `.solid` decoder brings the merged registry to **240**. All 12 original bot formats are included in that registry.

There is no separate fallback or engine-selection switch. Missing dependencies, rejected authentication, and invalid credentials fail explicitly.

The merged variants include SocksIP VER2/5/7/8, historical SocksHTTP keys, authenticated EHI configData and field encodings, password-protected V2Box, strict OpenTunnel XML, NetMod links/zero padding, HTTP Custom field encodings, DarkTunnel binary/JSON normalization, and SSC URI/field variants. Existing NPV whitebox output matched the uploaded engine on 20 block vectors; HAT/ZIV crypto profiles were already included. Thin root filenames preserve `run(bytes)` and CLI entry points; implementation classes/constants from the retired modules are not public interfaces.

The Worker accepts all 240 suffixes, including the compound `.sksrv.png`. Its `/formats` command sends the full list in bounded Telegram messages; welcome captions remain short. Both GitHub workflows include the complete imported package and data tables. Existing group/channel access policy is not changed by this import.

## Verify the exact import

From this repository:

```sh
python scripts/verify_import.py
python scripts/verify_import.py --archive ../attached_assets/SP-DECODE_1.1.4_Python_Decoders_TLS_Fixed_1791947086283.zip
python vendor/spdecode_python/tests/test_ports.py
python -m unittest discover -s tests -p 'test_*.py' -v
node --test tests/worker.test.mjs
```

The archive comparison checks the entire upstream inventory and every unchanged byte; it explicitly permits only the eight documented merge files and four additions. The updated fixed tree digest checks every byte of the tested merged engine even without the ZIP. The separately extracted ZIP reference stays unchanged.

## Limits

The uploaded suite uses synthetic configurations and saved reference vectors. Its update notes report selected real-export checks, but those exports are not included in the upload. Passing these tests does not certify every exporter version, credentials, VPN connectivity, or live Telegram/Cloudflare/GitHub deployment.

No real user configuration or credentials are added to this repository. Tests use local synthetic data and mocked network requests.
