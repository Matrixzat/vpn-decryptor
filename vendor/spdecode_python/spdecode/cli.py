import argparse
import json
from pathlib import Path
import sys
from .api import decode,formats

def main(allowed_suffixes=None):
    parser=argparse.ArgumentParser(description='Python decoder port from SP-DECODE 1.1.4')
    parser.add_argument('input',nargs='?',type=Path,help='Exported configuration file')
    parser.add_argument('--suffix',help='Explicit format; inferred from filename otherwise')
    parser.add_argument('-o','--output',type=Path,help='Write decoded JSON/text to a file')
    parser.add_argument('--password',help='User-defined HC password when required')
    parser.add_argument('--hwid',help='Authorized HWID for HWID-bound HC exports')
    parser.add_argument('--list',action='store_true',help='List registered suffixes')
    args=parser.parse_args()
    if args.list:
        names=[e['suffix'] for e in formats() if allowed_suffixes is None or e['suffix'] in allowed_suffixes]
        if allowed_suffixes is None or 'solid' in allowed_suffixes:names.append('solid')
        print('\n'.join(names));return 0
    if args.input is None:parser.error('input is required unless --list is used')
    suffix=args.suffix or ('sksrv.png' if args.input.name.lower().endswith('.sksrv.png') else args.input.suffix.lstrip('.'))
    suffix=suffix.lower().lstrip('.')
    if not suffix and allowed_suffixes and len(allowed_suffixes)==1:suffix=allowed_suffixes[0]
    if allowed_suffixes is not None and suffix not in allowed_suffixes:parser.error('This script supports: '+', '.join(allowed_suffixes))
    try:
        result=decode(args.input.read_bytes(),suffix,args.password,args.hwid)
        rendered=result if isinstance(result,str) else json.dumps(result,ensure_ascii=False,indent=2,default=str)
        if args.output:args.output.write_text(rendered+'\n')
        else:print(rendered)
        return 0
    except Exception as e:
        print('Decode failed: '+str(e),file=sys.stderr);return 1
