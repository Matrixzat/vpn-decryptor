"""NPV and NPVS table engines translated from L2.b and M1.U."""
from .common import *

SHIFT=[0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11]
def merge_tables(state,words,tables,base):
    out=[0]*16
    def lookup(index,a,b):return tables[base+index*256+a*16+b]
    for col in range(4):
        w=[words[(col*4+i)*256+state[col*4+i]] for i in range(4)]
        for row in range(4):
            index=row*6+col*24;hi=28-row*8;lo=24-row*8
            a=lookup(index,(w[0]>>hi)&15,(w[1]>>hi)&15)
            b=lookup(index+1,(w[2]>>hi)&15,(w[3]>>hi)&15)
            c=lookup(index+2,(w[0]>>lo)&15,(w[1]>>lo)&15)
            d=lookup(index+3,(w[2]>>lo)&15,(w[3]>>lo)&15)
            out[col*4+row]=(lookup(index+4,a,b)<<4)|lookup(index+5,c,d)
    return out
def npv_block(block):
    table=raw_asset('npv_whitebox.bin')
    if table[:8]!=b'NPWA0001':raise DecodeError('Invalid NPV whitebox')
    xor=table[8:24584];words_a=struct.unpack('>4096I',table[24584:40968]);words_b=struct.unpack('>4096I',table[40968:57352]);final=table[57352:]
    state=[block[i] for i in SHIFT]
    state=merge_tables(state,words_a,xor,0);state=merge_tables(state,words_b,xor,0)
    state=[state[i] for i in SHIFT]
    return bytes(final[i*256+v] for i,v in enumerate(state))
def npvs_block(block):
    table=raw_asset('npvs_v5_tables.bin');rounds=table[0]-1
    if rounds!=13 or len(table)!=749569:raise DecodeError('Invalid NPVS whitebox')
    first_offset=1+rounds*24576;final_offset=first_offset+rounds*16384;second_offset=final_offset+4096
    state=list(block)
    for r in range(rounds):
        state=[state[i] for i in SHIFT]
        a=struct.unpack('>4096I',table[first_offset+r*16384:first_offset+(r+1)*16384])
        b=struct.unpack('>4096I',table[second_offset+r*16384:second_offset+(r+1)*16384])
        state=merge_tables(state,a,table,1+r*24576);state=merge_tables(state,b,table,1+r*24576)
    state=[state[i] for i in SHIFT]
    return bytes(table[final_offset+i*256+v] for i,v in enumerate(state))
def npv(data):
    s=text(data).strip()
    for prefix in ['NPVTSUB1','NPVT1']:
        if s.startswith(prefix):s=s[len(prefix):].strip();break
    parts=s.split(',')
    if len(parts)<2:raise DecodeError('Invalid NPV envelope')
    record=b64(parts[1]);counter=int.from_bytes(record[:16],'big');out=bytearray()
    for pos in range(16,len(record),16):
        stream=npv_block(counter.to_bytes(16,'big'));counter=(counter+1)%2**128
        out.extend(a^b for a,b in zip(record[pos:pos+16],stream))
    obj=parse(bytes(out))
    return obj[0] if isinstance(obj,list) and obj and isinstance(obj[0],dict) else obj
def canonical(obj):
    s=json.dumps(obj,ensure_ascii=False,sort_keys=True,separators=(',',':'))
    return s.replace('&','\\u0026').replace('<','\\u003c').replace('>','\\u003e').replace('\u2028','\\u2028').replace('\u2029','\\u2029').encode()
def npvs(data):
    from cryptography.hazmat.primitives.asymmetric import ec,utils
    from cryptography.hazmat.primitives import hashes
    if len(data)<89 or data[:5]!=b'NPVS\5':raise DecodeError('Invalid NPVS v5 header')
    n=struct.unpack('>I',data[5:9])[0];end=n+9
    if not 135<=n<=262144 or end+80>len(data):raise DecodeError('Invalid NPVS auxiliary length')
    aux=data[9:end]
    if aux[0]!=1 or aux[50]!=2:raise DecodeError('Invalid NPVS auxiliary version')
    count=struct.unpack('>H',aux[51:53])[0];offset=count*125
    if count>1024 or offset+135>len(aux) or aux[offset+53:offset+55]!=b'\0\2':raise DecodeError('Invalid NPVS recipient layout')
    metalen=struct.unpack('>I',aux[offset+131:offset+135])[0]
    if metalen<16 or metalen!=len(aux)-offset-135:raise DecodeError('Invalid NPVS metadata length')
    fieldslen=struct.unpack('>I',data[end+12:end+16])[0]
    if fieldslen<70 or end+16+fieldslen+64!=len(data):raise DecodeError('Invalid NPVS fields length')
    public=aux[17:50];key=ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(),public)
    signature=data[-64:];r=int.from_bytes(signature[:32],'big');s=int.from_bytes(signature[32:],'big')
    key.verify(utils.encode_dss_signature(r,s),data[:-64],ec.ECDSA(hashes.SHA256()))
    block=aux[offset+55:offset+71];wrapped=aux[offset+71:offset+131];config_id=aux[1:17]
    appkey=sha(b'npvtunnel/appkey/v2 '+npvs_block(block)+config_id)
    document_key=chacha(appkey,wrapped[:12],wrapped[12:],block)
    nonce=data[end:end+12]
    def derive(ikm,salt,info):return mac(mac(salt,ikm),info+b'\1')
    metadata=json.loads(text(chacha(derive(document_key,nonce,b'NPVS-v5/metadata'),nonce,aux[offset+135:],aux[:offset+131])))
    policy=metadata['policy']
    normalized={k:policy.get(k,default) for k,default in [('onlyMobileNetwork',False),('attestationLevel',''),('expiresAt',None),('displayMessage',''),('customServerMessage','')]}
    if policy.get('configVersion') not in (None,False,0,''):normalized['configVersion']=policy['configVersion']
    url=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
    source={'v':5,'configId':url(config_id),'issuedAt':metadata.get('issuedAt',''),'creator':{'fp':url(sha(public)),'pk':url(public)},'policy':normalized,'recipients':None}
    fingerprint=sha(b'NPVS-v5/source-fields-v1/'+canonical(source)+nonce)
    fields=data[end+16:-64]
    if fields[:4]!=b'NPF\1' or not hmac.compare_digest(fields[4:36],fingerprint):raise DecodeError('NPVS source fingerprint mismatch')
    def field_key(label,id):return derive(document_key,fingerprint,b'NPV-fields-v1/'+label+b'/'+struct.pack('>H',id))
    if not hmac.compare_digest(mac(field_key(b'inventory',0),fields[:-32]),fields[-32:]):raise DecodeError('NPVS inventory HMAC mismatch')
    count=struct.unpack('>H',fields[36:38])[0];pos=38;records={};last=0
    for _ in range(count):
        id,length=struct.unpack('>HI',fields[pos:pos+6]);pos+=6
        if not last<id or not 16<=length<=1048592 or length>len(fields)-32-pos:raise DecodeError('Invalid NPVS field record')
        aad=b'NPV-fields-v1/record/'+fingerprint+struct.pack('>HI',id,length-16)
        records[id]=json.loads(text(chacha(field_key(b'field',id),bytes(12),fields[pos:pos+length],aad)));pos+=length;last=id
    if pos!=len(fields)-32 or 65535 not in records:raise DecodeError('Invalid NPVS inventory root')
    used=set()
    def resolve(obj):
        if isinstance(obj,dict):return {k:resolve(v) for k,v in obj.items()}
        if isinstance(obj,list):return [resolve(v) for v in obj]
        if not isinstance(obj,int) or not 1<=obj<65535 or obj not in records:raise DecodeError('Invalid NPVS field reference')
        used.add(obj);value=records[obj]
        if isinstance(value,(dict,list)):raise DecodeError('NPVS leaf has invalid type')
        return value
    document=resolve(records[65535])
    if used!=set(records)-{65535} or not isinstance(document.get('configs'),list):raise DecodeError('NPVS reference inventory mismatch')
    def decode_value(v):
        if not v.startswith('npvs1:'):return v
        return parse(b64url(v[6:]))
    return walk({'metadata':metadata,'document':document},decode_value)
