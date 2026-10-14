#!/usr/bin/env python3
"""Python port for decoders/Python/ultra.py. Keep the sibling spdecode package and data directory."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from spdecode.api import decode as _decode
from spdecode.cli import main
SUPPORTED_SUFFIXES = ['ultratunnel', 'mtv2raypro', 'wolftunnel', 'flynetvpn', 'nurtunnel', 'tiktunnel', 'mdproxy', 'mtv2ray', 'flynet', 'glory', 'great', 'lucky', 'marvs', 'mdvpn', 'mehaf', 'ultra', 'aura', 'deep', 'ulti', 'wolf', 'bcl', 'bee', 'btv', 'ena', 'eta', 'fix', 'mdp', 'mmt', 'nur', 'osv', 't10', 't20', 'tik', 'tsm', 'vel', 'vlx', 'md', 'mm', 'ry', 'tx', 'ut']

def decode(data, suffix=None, password=None, hwid=None):
    """Return raw decoded configuration data; shared engines are native Python."""
    if suffix is None:
        if len(SUPPORTED_SUFFIXES) != 1:
            raise ValueError('Specify suffix: '+', '.join(SUPPORTED_SUFFIXES))
        suffix = SUPPORTED_SUFFIXES[0]
    suffix = suffix.lower().lstrip('.')
    if suffix not in SUPPORTED_SUFFIXES:
        raise ValueError('Unsupported suffix for this script: '+suffix)
    return _decode(data,suffix,password,hwid)

if __name__ == '__main__':
    raise SystemExit(main(SUPPORTED_SUFFIXES))
