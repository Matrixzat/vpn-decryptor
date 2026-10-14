"""Merged container validation and password-aware V2Box exports."""
from .common import *

def v2box(data,password=None):
    profiles=asset('embedded_kotlin_profiles.json')['specialKeyFamilies']['e1']
    s=strip_uri(data).lstrip('\ufeff').split('locked=',1)[-1]
    try:obj=json.loads(s)
    except ValueError:obj=json.loads(text(b64url(s)).lstrip('\ufeff'))
    if not isinstance(obj,dict) or obj.get('magic')!='v2box_export':
        raise DecodeError('Invalid V2Box signature')
    version=obj.get('version')
    if isinstance(version,bool) or version!=1:raise DecodeError('Unsupported V2Box version')
    protected=obj.get('isPasswordProtected',False)
    if not isinstance(protected,bool):raise DecodeError('Invalid V2Box password flag')
    nonce,ciphertext,tag=map(b64,[obj['nonce'],obj['ciphertext'],obj['tag']])
    if len(nonce)!=12 or len(tag)!=16 or not ciphertext:
        raise DecodeError('Invalid V2Box GCM record')
    if protected:
        if not password:raise DecodeError('V2Box requires the authorized export password')
        keys=[sha(password.encode('utf-8'))]
    else:
        key=bytes.fromhex(profiles['v2boxKeyHex']);keys=list(dict.fromkeys([key,sha(key)]))
    def attempt(key):
        result=json.loads(text(gcm(key,nonce,ciphertext+tag)))
        if not isinstance(result,dict):raise DecodeError('V2Box payload must be a JSON object')
        return result
    return first([lambda key=key:attempt(key) for key in keys])
