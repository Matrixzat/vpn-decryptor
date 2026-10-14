#!/usr/bin/env python3
"""Verify every imported byte, the catalog, and the Worker format registry."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import zipfile

if __package__:
    from .ported_engine import ROOT, formats
else:
    from ported_engine import ROOT, formats

EXPECTED_FILES = 123
ORIGINAL_TREE_SHA256 = "30678d95f4c70da16cc9a3d94c87e28f72fde325a12714b9a8712533524357c0"
EXPECTED_TREE_SHA256 = "673c20ccd68caf0d911a4b5c47cdc254ccfb558a0fa71034aac35936c88ce8a0"
MERGED_UPSTREAM_FILES = {
    "spdecode/api.py", "spdecode/batch_legacy.py", "spdecode/common.py",
    "spdecode/httpcustom.py", "spdecode/injector.py", "spdecode/legacy.py",
    "spdecode/misc.py", "spdecode/special.py",
}
ADDED_ENGINE_FILES = {
    "spdecode/containers.py", "spdecode/hc_fields.py",
    "spdecode/sockshttp.py", "spdecode/socksip.py",
}


def imported_files(root: Path = ROOT) -> dict[str, Path]:
    folder = root / "vendor/spdecode_python"
    return {
        str(path.relative_to(folder)): path
        for path in folder.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and path.suffix != ".pyc"
    }


def tree_digest(files: dict[str, Path]) -> str:
    digest = hashlib.sha256()
    for name in sorted(files):
        digest.update(name.encode("utf-8") + b"\0")
        digest.update(hashlib.sha256(files[name].read_bytes()).digest())
    return digest.hexdigest()


def worker_suffixes(root: Path = ROOT) -> set[str]:
    text = (root / "worker.js").read_text(encoding="utf-8")
    match = re.search(r'var SPDECODE_SUFFIXES = "([^"]+)"\.split\(" "\)', text)
    if match is None:
        raise ValueError("Worker SP-DECODE registry is missing")
    region = text.split("var SUPPORTED_FORMATS", 1)[1].split("]);", 1)[0]
    retained = set(re.findall(r'\["\.([^"]+)",', region))
    return retained | set(match.group(1).split())


def verify(root: Path = ROOT, archive: Path | None = None) -> dict[str, int | str]:
    files = imported_files(root)
    if len(files) != EXPECTED_FILES or tree_digest(files) != EXPECTED_TREE_SHA256:
        raise ValueError("Unified engine inventory or byte fingerprint differs from the verified merge")
    if archive:
        with zipfile.ZipFile(archive) as zipped:
            originals = {
                info.filename.removeprefix("spdecode_python/"): info
                for info in zipped.infolist() if not info.is_dir()
            }
            if set(originals) | ADDED_ENGINE_FILES != set(files):
                raise ValueError("ZIP and imported package have different inventories")
            source_digest = hashlib.sha256()
            for name in sorted(originals):
                source_digest.update(name.encode("utf-8")+b"\0")
                source_digest.update(hashlib.sha256(zipped.read(originals[name])).digest())
            if source_digest.hexdigest()!=ORIGINAL_TREE_SHA256:
                raise ValueError("This is not the original uploaded package")
            for name, info in originals.items():
                if name not in MERGED_UPSTREAM_FILES and zipped.read(info) != files[name].read_bytes():
                    raise ValueError(f"Byte mismatch: {name}")
    expected = set(formats(root))
    actual = worker_suffixes(root)
    if actual != expected:
        raise ValueError(f"Worker format mismatch: missing={sorted(expected-actual)}, extra={sorted(actual-expected)}")
    return {
        "files": len(files),
        "bytes": sum(path.stat().st_size for path in files.values()),
        "suffixes": len(expected),
        "tree_sha256": EXPECTED_TREE_SHA256,
        "upstream_files": 119,
        "merged_upstream_files": len(MERGED_UPSTREAM_FILES),
        "added_engine_files": len(ADDED_ENGINE_FILES),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, help="Original ZIP for an additional byte-by-byte comparison")
    args = parser.parse_args()
    try:
        result = verify(archive=args.archive)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"FAIL: {error}")
        return 1
    print(f"PASS: verified {result['files']} engine/package files; {result['suffixes']} formats are wired to the Worker")
    print("All 119 upstream files retained: 111 byte-identical, 8 deliberately merged; 4 new engine modules")
    print(f"Imported tree SHA-256: {result['tree_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
