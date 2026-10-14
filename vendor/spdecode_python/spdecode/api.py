"""Public API and exact catalog routing for all 239 registered suffixes."""
from .common import *
from .families import generic,ultra
from .renz import renz
from .special import special
from .independent import independent
from .legacy import legacy
from .batch_legacy import batch
from .injector import injector
from .whitebox import npv,npvs
from .linklayer import linklayer
from .httpcustom import httpcustom
from .misc import misc

BATCH={'tls','phc','ziv','cloudy','gold','sks','ssh','ht','htb','npv2','epro','hat','dark','sip','tnl'}
MISC={'ssc','hrt','jez','maya','solid'}
INJECTOR={'ehi','ehil'}
LEGACY={'fnnetwork','mij','mrc','mtl','uwu','nt','pb','pcx','sksrv.png','sksrv','agn','cly','fɴ','jvc','jvi','v2i','sbr','ost','stk','rez','rezl','tvt','ipt','at','aro','nm','mina','vpnlite','xtp','roy','sut','sksplus','xscks','xui','v2'}
CATALOG={e['suffix']:e for e in asset('decoder_catalog.json')['entries']}

def formats():return list(CATALOG.values())
def decode(data,suffix,password=None,hwid=None):
    suffix=suffix.lower().lstrip('.')
    if isinstance(data,str):data=data.encode()
    if not isinstance(data,bytes) or not data or len(data)>LIMIT:raise DecodeError('Input must contain 1 to 16777216 bytes')
    if password is not None and suffix not in {'hc','v2box'}:raise DecodeError('This format does not accept a supplied password')
    if hwid is not None and suffix!='hc':raise DecodeError('This format does not accept a supplied HWID')
    entry=CATALOG.get(suffix)
    if entry is None and suffix!='solid':raise DecodeError('Unknown decoder suffix: '+suffix)
    phase=entry['migrationPhase'] if entry else 'legacy'
    if phase=='B':return generic(data,suffix)
    if phase=='C':return ultra(data,suffix)
    if phase=='D':return renz(data,suffix)
    if phase=='E':return special(data,suffix,password=password)
    if phase=='F':return independent(data,suffix)
    if suffix in BATCH:return batch(data,suffix)
    if suffix in MISC:return misc(data,suffix)
    if suffix in INJECTOR:return injector(data,suffix)
    if suffix in {'npv4','npvt'}:return npv(data)
    if suffix=='npvs':return npvs(data)
    if suffix=='lnk':return linklayer(data)
    if suffix=='hc':return httpcustom(data,password,hwid)
    if suffix in LEGACY:return legacy(data,'sksrv.png' if suffix=='sksrv' else suffix)
    raise DecodeError('Decoder routing missing: '+suffix)
