"""One SocksHTTP decoder covering all compared APK key generations."""
from .common import *

def sockshttp(data):
    obj=json.loads(text(data))
    version=obj.get('v')
    if isinstance(version,bool) or not isinstance(version,int) or version<0:
        raise DecodeError('Invalid SocksHTTP version')
    if not isinstance(obj.get('d'),str) or obj['d'].count('.')!=1:
        raise DecodeError('Invalid SocksHTTP ciphertext/IV')
    encrypted,iv=map(b64,obj['d'].split('.'))
    if not encrypted or len(encrypted)%16 or len(iv)!=16:
        raise DecodeError('Invalid SocksHTTP AES record')
    keys=[]
    if version<5:keys.append(b'662ede816988e58fb6d057d9d85605e0')
    elif version==5:keys.append(b'962exe865948e37ws6d057d4d85604e0')
    prefix=asset('embedded_kotlin_profiles.json')['legacyBatch2']['sks']['configKey']+' '
    for seed in [prefix,'162exe235948e37ws6d057d9d85324e2 ','962exe865948e37ws6d057d4d85604e0 ']:
        keys.append(md5((seed+str(version)).encode('ascii')).hex().encode('ascii'))
    def attempt(key):
        result=json.loads(text(cbc(key,iv,encrypted)))
        if not isinstance(result,dict):raise DecodeError('SocksHTTP payload must be a JSON object')
        return result
    return first([lambda key=key:attempt(key) for key in dict.fromkeys(keys)])
