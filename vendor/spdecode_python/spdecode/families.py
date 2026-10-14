"""Catalog phases B and C. Sources: M1.AbstractC0361t and M1.y0."""
from .common import *

def generic(data,suffix):
    profile=next((p for p in asset('generic_b_profiles.json')['profiles'] if p['suffix']==suffix),None)
    if profile is None:raise DecodeError('No profile for this suffix')
    attempts=[]
    if profile.get('desKey'):
        key=b64(profile['desKey'])
        candidates=[data]
        try:candidates.append(b64(data))
        except ValueError:pass
        attempts += [lambda d=d:require_config(des(key,d)) for d in candidates if len(d)%8==0]
    for password in profile.get('aesKeys',[]):
        attempts.append(lambda p=password:parse(triplet(data,b64(p))))
    return first(attempts)

def ultra(data,suffix):
    from argon2.low_level import hash_secret_raw,Type
    catalog=asset('ultra_c_profiles.json')
    profiles={p['key']:p for p in catalog['profiles']}
    alias=next((a for a in catalog['aliases'] if a['suffix']==suffix),{'profile':'default','name':'OST TUNNEL'})
    cleaned=re.sub(r'[^A-Za-z0-9+/=]','',strip_uri(data))
    candidates=[cleaned]
    if len(cleaned)%4==1:candidates += [cleaned[:i]+cleaned[i+1:] for i in range(min(16,len(cleaned)))]
    priority=list(dict.fromkeys([alias['profile']]+catalog['fallbackProfiles']+list(profiles)))
    def derive(profile,password,salt):
        return hash_secret_raw(b64(profile[password]),salt,time_cost=catalog['argonIterations'],
            memory_cost=profile['memoryKiB'],parallelism=catalog['argonLanes'],hash_len=32,type=Type.ID,version=19)
    def decrypt_record(record,p,password):
        if len(record)<44:raise DecodeError('Ultra record too short')
        salt,nonce,enc=record[:16],record[16:28],record[28:]
        key=derive(p,password,salt)
        return first([lambda:gcm(key,nonce,enc,salt),lambda:gcm(key,nonce,enc)])
    def attempt(candidate,key):
        p=profiles[key]
        plain=decrypt_record(b64(candidate),p,'password')
        s=text(plain);start=s.find('{');end=s.rfind('}')
        if start<0 or end<start:raise DecodeError('No Ultra JSON')
        config=json.loads(s[start:end+1])
        for name in catalog['encryptedFields']:
            if isinstance(config.get(name),str) and len(config[name])>=44:
                try:config[name]=text(decrypt_record(b64(config[name]),p,'password2'))
                except (ValueError,UnicodeError):pass
        config['_vpn_type']=p['name'];config['_vpn_key']=p['key']
        return {'application':alias['name'],'extension':'.'+suffix,'config':config}
    return first([lambda c=c,k=k:attempt(c,k) for c in candidates for k in priority])
