"""Ports of remaining table/profile-driven legacy crypto (M1.C0353k)."""
from .common import *

def tls(data):
    s=re.sub(r'\s','',strip_uri(data)).split(':',1)[0]
    record=b64(s[::-1])
    if len(record)<148:raise DecodeError('TLS record too short')
    n=len(record);half=(n-132)//2
    encrypted=record[12:12+half][::-1]+record[30+half:n-102][::-1]
    nonce=record[12+half:30+half][::-1]+record[n-102:n-84][::-1]
    profiles=asset('embedded_kotlin_profiles.json')['tls']['hexProfiles']
    attempts=[]
    for i,key in enumerate(profiles,1):
        def attempt(key=key,i=i):
            plain=text(gcm(bytes.fromhex(key),nonce,encrypted));v=plain.split(':')
            encoded={4,5,6,7,9,12,14,16,18,19,24,27}
            def field(index):
                s=v[index] if index<len(v) else ''
                if index in encoded:
                    try:return text(b64(s))
                    except (ValueError,UnicodeError):pass
                return s
            names=['tlsvpnVersion','server','port','pserver','sshuser','sshpass','sshhost','server_port',None,'sshport','metodo','upayload','payload','usnihost','snihost','upayloadat','payloadat','uproxy','prxhost','prxport']
            result={name:field(j) for j,name in enumerate(names) if name is not None}
            for name in ['tlsvpnVersion','server','port','metodo']:
                try:result[name]=int(result[name])
                except ValueError:result[name]=0
            for name in ['pserver','upayload','usnihost','upayloadat','uproxy']:result[name]=result[name].lower()=='true'
            if i==6:
                for j,name in enumerate(['legacy_dns_mode','dnsP','dns_port','nameserver','public_key'],20):result[name]=field(j)
            result['bloqmc']=field(25).lower()=='true'
            result['mensagem']=field(27).replace('Ѻ','\n').replace('ѻ','\r')
            result['_tls']={'authenticated':True,'key_profile':i,'field_count':len(v),'fields':[{'index':j,'raw':s,'value':field(j)} for j,s in enumerate(v)]}
            return result
        attempts.append(attempt)
    return first(attempts)

def batch(data,suffix):
    all_profiles=asset('embedded_kotlin_profiles.json');p=all_profiles['legacyBatch2']
    if suffix=='tls':return tls(data)
    if suffix in {'phc','ziv'}:
        passwords=all_profiles['independentF1']['vn7Passwords']
        if suffix=='phc':passwords=passwords[1:2]
        return first([lambda password=password:parse(triplet(data,password)) for password in passwords[::-1]])
    if suffix=='cloudy':return require_config(cbc(b64(p['cloudy']['aesKeyB64']),b64(p['cloudy']['ivB64']),b64(data)))
    if suffix=='gold':
        key=sha(p['gold']['hashSeed'].encode())
        obj=require_config(cbc(key,bytes(16),b64(data)))
        if isinstance(obj.get('network'),str):obj['network']=json.loads(obj['network'].replace('\\"','"').replace('ALUKt53Zd7wN6SoBNpv2lw==',''))
        def decrypt(v):
            if len(v)<=20 or '=' not in v:return v
            s=text(cbc(key,bytes(16),b64(v)))
            mapping=asset('ported_constants.json').get('goldMap',{})
            return ''.join(mapping.get(c,c) for c in s)
        return walk(obj,decrypt)
    if suffix=='sks':
        from .sockshttp import sockshttp
        return sockshttp(data)
    if suffix=='ssh':
        key=p['ssh']['blowfishPassword'].encode('ascii')
        plain=unpad(Blowfish.new(key,Blowfish.MODE_CBC,bytes(range(8))).decrypt(b64(data)),8)
        return require_config(plain)
    if suffix in {'ht','htb'}:
        record=b64(data)
        if len(record)<33 or len(record)%16!=1:raise DecodeError('Invalid HTTP Tweak length')
        tables=asset('http_tweak_source_tables.json')[str(record[0])]
        keys,perms,subs=map(b64,[tables['round_keys'],tables['permutations'],tables['substitutions']])
        inverse=[]
        for r in range(12):
            table=bytearray(256)
            for i,v in enumerate(subs[r*256:(r+1)*256]):table[v]=i
            inverse.append(table)
        previous=record[1:17];plain=bytearray()
        for start in range(17,len(record),16):
            block=record[start:start+16];state=bytearray(block)
            for r in range(11,-1,-1):
                result=bytearray(16)
                for i in range(16):result[perms[r*16+i]&15]=state[i]^keys[r*16+i]
                state=bytearray(inverse[r][x] for x in result)
            plain.extend(a^b for a,b in zip(state,previous));previous=block
        return require_config(decompress(bytes(plain)))
    if suffix=='npv2':
        s=text(data)
        return first([lambda password=password:json.loads(''.join(chr((ord(c)-ord(password[i%len(password)]))&0xffff) for i,c in enumerate(s))) for password in asset('legacy_epro_npv2_keys.json')['npv2Passwords']])
    if suffix=='epro':
        candidates=[data];alphabet='。〃〄々〆〇〈〉《》「」『』【】〒〓〔〕'
        try:
            s=''.join(c for c in text(data) if not 8192<=ord(c)<8432 and c not in '\n\r')
            candidates.append(b64(''.join(chr(ord(c)^ord(alphabet[i%len(alphabet)])) for i,c in enumerate(s))))
        except (ValueError,UnicodeError):pass
        names={
            '[splitConfig]':['payload','proxyURL','blockedRoot','lockPayloadAndServers','expireDate','containsNotes','note1','sshAddr','mobileData','unlockProxy','openVPNConfig','VPNAddr','sniValue','connectSSH','udpgwPort','lockPayload','hwidEnabled','hwidValue','note2','unlockUserAndPassword','sslPayloadMode','passwordProtected','passwordValue'],
            '[pisahConk]':['payload','proxyAddress','proxyPort','autoReplace','route','connectSSH','useTun2Socks','googlePlay','mobileData','customPayload','hwidEnabled','unknown1','unknown2','hwidValue','note1','bitviseProfileName','sshServer','sshPort','sshUser','sshPassword','bool','autoReconnect','enableCustomDNS','enableHTTPProxy','httpProxy','extraProtection','blockedRoot','unknown3','listenPort','useDNS','dnsForward','batterySaver','showLog','expireDate','directSSH']}
        def attempt(password,record):
            s=text(ecb(hashlib.sha1(password.encode()).digest()[:16],record))
            for delimiter,fields in names.items():
                if delimiter in s:return dict(zip(fields,s.split(delimiter)))
            raise DecodeError('No ePro delimiter')
        return first([lambda password=password,r=r:attempt(password,r) for password in asset('legacy_epro_npv2_keys.json')['eproPasswords'][0] for r in candidates if len(r)%16==0])
    if suffix=='hat':
        obj=parse(ecb(b64(all_profiles['hat']['aesKeyB64']),b64(data)))
        p5=obj.get('profilev5') if isinstance(obj,dict) else None
        if isinstance(p5,dict):
            password=all_profiles['hat']['profileV5XorPassword']
            for key in ['connection_mode','custom_payload','custom_host','custom_sni']:
                if isinstance(p5.get(key),str):
                    s=text(b64(p5[key]));p5[key]=''.join(chr(ord(c)^ord(password[i%len(password)])) for i,c in enumerate(s))
        return obj
    if suffix=='dark':
        import msgpack
        p=all_profiles['dark'];iv=bytes.fromhex(p['ivHex']);outer=p['outerKeyText'].encode();nested=p['nestedKeyText'].encode()
        obj=require_config(b64url(strip_uri(data)))
        decoded=msgpack.unpackb(cfb(outer,iv,b64url(obj['encryptedLockedConfig'])),raw=False,strict_map_key=False)
        def visit(value):
            if isinstance(value,dict):
                result={}
                for key,v in value.items():
                    if isinstance(v,bytes) and isinstance(key,str) and key.startswith('Encrypted'):
                        try:
                            v=cfb(nested,iv,v)
                            if key=='EncryptedLockedConfig':v=msgpack.unpackb(v,raw=False,strict_map_key=False)
                        except ValueError:pass
                    result[key]=visit(v)
                return result
            if isinstance(value,list):return [visit(x) for x in value]
            if isinstance(value,bytes):
                for record in [value,cfb(nested,iv,value)]:
                    try:
                        decoded=record.decode()
                        if all(c.isprintable() or c in '\r\n\t' for c in decoded):
                            return parse(decoded)
                    except UnicodeError:pass
                return {'binary_base64':base64.b64encode(value).decode()}
            if isinstance(value,str) and value.lstrip().startswith(('{','[')):
                try:return json.loads(value)
                except ValueError:pass
            return value
        obj['encryptedLockedConfig']=visit(decoded);return obj
    if suffix=='sip':
        from .socksip import socksip
        return socksip(data)
    if suffix=='tnl':
        p=p['tnl']
        if data[:4]==b'OPL\2':
            if len(data)<12:raise DecodeError('Truncated OPL header')
            n=struct.unpack('<I',data[4:8])[0]^((-1481390639)&0xffffffff)
            if n!=len(data)-12:raise DecodeError('Invalid OPL length or trailing data')
            s=bytes(v^((((195<<(i%8))|(195>>(8-i%8)))&255))^(i&255) for i,v in enumerate(data[12:12+n]))
            if zlib.crc32(s)!=struct.unpack('<I',data[8:12])[0]:raise DecodeError('OPL CRC mismatch')
            parts=s.split(b'.')
            if len(parts)!=3 or len(b64(parts[0]))!=32 or len(b64(parts[1]))!=12:
                raise DecodeError('Invalid OPL envelope')
            return parse(triplet(s,p['oplSecret'],100000,32))
        if '.' in text(data):return first([lambda password=password:parse(triplet(data,password)) for password in p['passwords']])
        record=b64(data);seed,n=struct.unpack('>II',record[:8])
        if n>len(record)-8:raise DecodeError('Invalid OT length')
        key=bytes.fromhex(p['otKeyHex']);plain=bytearray()
        for i,c in enumerate(record[8:8+n]):
            v=c^((i*7+13)&255)
            plain.append((((v<<5)|(v>>3))&255)^((seed>>((i*8)&24))&255)^key[i%32])
        return require_config(bytes(plain))
    raise DecodeError('Legacy batch format not mapped: '+suffix)
