"""Special phase E formats, translated from M1.k0, M1.l0 and M1.m0."""
from .common import *

def special(data,suffix,password=None):
    materials=asset('embedded_kotlin_profiles.json')['specialKeyFamilies']
    e1,e2=materials['e1'],materials['e2']
    s=strip_uri(data)
    if suffix in {'apnalite','apnatnl','bdnet','hxt','fnf','4ulite','omanova','ursa','hsome'}:
        key=b'4%PdXch>fkP]'
        def decrypt(v):
            decoded=bytes.fromhex(v)
            return text(bytes(x^key[i%len(key)] for i,x in enumerate(decoded)))
        return walk(parse(decrypt(s)),decrypt)
    if suffix=='itv':
        if len(data)<44:raise DecodeError('ITV input too short')
        return parse(ctr(data[:32],data[32:44]+b'\0\0\0\2',data[44:]))
    if suffix in {'juanscript','juan','mobi'}:
        if s.startswith('2:'):s=s[2:]
        encoded,checksum=s.rsplit('.',1)
        if sha(encoded.encode())[:8].hex().lower()!=checksum.lower():raise DecodeError('JuanScript checksum mismatch')
        record=b64url(encoded);length=struct.unpack('>I',record[:4])[0]
        if not 1<=length<=64:raise DecodeError('Invalid JuanScript salt length')
        salt=record[4:4+length];pos=4+length
        n=struct.unpack('>I',record[pos:pos+4])[0];pos+=4
        if n!=12:raise DecodeError('Invalid JuanScript nonce length')
        plain=gcm(pbkdf(e1['juanPassword'],salt,120000,32),record[pos:pos+n],record[pos+n:])
        return parse(maybe_decompress(plain))
    if suffix=='v2box':
        from .containers import v2box
        return v2box(data,password)
    if suffix=='eut':
        key=e1['eutPasswordLatin1'].encode('latin1')
        def value(v):
            if v.count(':')!=1:return v
            iv,enc=v.split(':',1)
            return parse(cbc(key,b64(iv),b64(enc)))
        try:obj=walk(parse(text(data)),value)
        except (ValueError,UnicodeError):obj=value(s)
        return walk(obj,value)
    if suffix=='st':
        record=bytearray(data)
        for pos in range(0,len(record),32):
            if pos+16<len(record):record[pos:pos+16]=record[pos:pos+16][::-1]
        k=e1['sentinelAscii'].encode('ascii')
        record=bytes(v^k[i%32] for i,v in enumerate(record))
        if record[:5]!=b'STCF\1':raise DecodeError('Invalid Sentinel header')
        obj=json.loads(text(record[5:]));conf=obj['configData']
        salt,iv,enc,tag=map(b64,[conf['keySalt'],conf['iv'],conf['data'],conf['hmac']])
        key=b64(obj['passwordHash']) if obj.get('passwordHash') else sha(k+salt)
        if not hmac.compare_digest(mac(key,iv+enc),tag):raise DecodeError('Sentinel HMAC mismatch')
        obj['configData']=parse(gcm(key,iv,enc));return obj
    if suffix=='slipnet':
        try:record=b64(s)
        except ValueError:record=data
        key=bytes.fromhex(e1['slipnetKeyHex'])
        plain=first([lambda off=off:gcm(key,record[off:off+12],record[off+12:]) for off in [1,0]])
        values=text(plain).split('|')
        names={0:'version',1:'tunnel_type',2:'name',3:'domain',6:'keepalive',7:'congestion',8:'tcp_port',9:'tcp_host',5:'gso',4:'dnstt_key',16:'ssh_enabled',14:'ssh_user',15:'ssh_pass',17:'ssh_port',18:'ssh_host',22:'dns_transport',23:'ssh_auth_type',24:'naive_port',25:'hwid',26:'expiry_timestamp',33:'locked',34:'authoritative_mode',27:'resolvers',36:'local_port',37:'dns_record_type',38:'proxy_port',39:'load_balance_mode',40:'tls_mode',20:'transport',41:'ws_path',28:'tls_port',42:'sni_mode',43:'mux_concurrency'}
        result={name:values[i] for i,name in names.items() if i<len(values) and values[i]}
        for name,index in [('tunnel_type',21),('tls_port',35)]:
            if not result.get(name) and index<len(values):result[name]=values[index]
        result.setdefault('ws_path','/');result.setdefault('sni_mode','sni_split');result.setdefault('mux_concurrency','8')
        return result
    if suffix=='ec':return parse(xxtea(b64(s),e2['ecPassword'].encode('ascii'),include_length=True))
    if suffix in {'fthp','ftp'}:return first([lambda p=p:parse(triplet(s,p)) for p in e2['fthpPasswords']])
    if suffix in {'ar','msy'}:
        key=bytes.fromhex(e2['arMainKeyHex'])
        obj=first([lambda:require_config(cbc(key,bytes(16),b64(s))),lambda:require_config(s),lambda:require_config(b64(s))])
        fields={'Payload','WSPayload','SNIHost','BUGHost','DNSHost','ProxySet','UDPhost','UDPobfs','UDPauth','V2Ejson','v2Esni','EwgConf','Server'}
        for k,v in list(obj.items()):
            if k in fields and isinstance(v,str) and v:
                def cfb_field():return text(cfb(bytes.fromhex(e2['arFieldKeyHex']),bytes.fromhex(e2['arFieldIvHex']),b64(v))).rstrip(''.join(map(chr,range(17))))
                try:obj[k]=first([cfb_field,lambda:text(cbc(key,bytes(16),b64(v)))])
                except (ValueError,UnicodeError):pass
        return obj
    if suffix=='int':
        def decrypt(v):
            if not v.startswith('djAx'):return v
            v=v[4:];return text(gcm(e2['intPassword'].encode(),b64(v[:16]),b64(v[16:])))
        return walk(parse(decrypt(s)),decrypt)
    if suffix=='wyr':
        def decrypt(v):
            record=b64(v);return text(gcm(e2['wyrPassword'].encode(),record[3:15],record[15:]))
        obj=parse(decrypt(s))
        if isinstance(obj,dict):
            for k in {'dnstt_dns','custom_proxy','custom_proxy_port','password','sni','http','v2ray_host','v2ray_json'}:
                if isinstance(obj.get(k),str) and obj[k].startswith('djAx'):
                    try:obj[k]=decrypt(obj[k])
                    except (ValueError,UnicodeError):pass
        return obj
    if suffix in {'wyrl','wyrvpnlite','wyrlite'}:
        derived=pbkdf(e2['wyrlPbkdfPassword'],b'',10000,32)
        def decrypt(v):
            record=b64(v)
            if len(record)<28:raise DecodeError('WyrLite record too short')
            nonce,tag,enc=record[:12],record[12:28],record[28:]
            return first([lambda:parse(chacha(bytes.fromhex(e2['wyrlChaChaKeyHex']),nonce,enc+tag)),lambda:parse(chacha(derived,nonce,enc+tag)),lambda:parse(gcm(derived,nonce,enc+tag))])
        try:obj=decrypt(s)
        except (ValueError,UnicodeError):obj=require_config(s)
        return walk(obj,decrypt)
    raise DecodeError('Special format not mapped: '+suffix)
