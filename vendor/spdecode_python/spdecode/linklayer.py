"""LinkLayer VER6 container and Go gob parser, translated from M1.L."""
from .common import *
from Crypto.Cipher import Salsa20,CAST

STATIC_IV=bytes.fromhex('a7734f9c12ac1b01a415f2c1fc78e66b')
def gob(data):
    class Reader:
        def __init__(self,data):self.data=data;self.pos=0
        def take(self,n):
            if n<0 or n>len(self.data)-self.pos:raise DecodeError('Truncated Go gob')
            s=self.data[self.pos:self.pos+n];self.pos+=n;return s
        def uint(self):
            first=self.take(1)[0]
            if first<128:return first
            n=256-first
            if n>8:raise DecodeError('Oversized Go gob integer')
            return int.from_bytes(self.take(n),'big')
        def sint(self):
            u=self.uint();return ~(u>>1) if u&1 else u>>1
        def string(self):return text(self.take(self.uint()))
        def expect(self,v):
            if self.uint()!=v:raise DecodeError('Unsupported Go gob descriptor')
    r=Reader(data);types={};result=None
    def default(t,depth=0):
        if depth>8:raise DecodeError('Go gob type recursion')
        if t==1:return False
        if t==2:return 0
        if t==6:return ''
        return {name:default(kind,depth+1) for name,kind in types[t][1]}
    def value(r,t,depth=0):
        if depth>8:raise DecodeError('Go gob value recursion')
        if t==1:return bool(r.uint())
        if t==2:return r.sint()
        if t==6:return r.string()
        fields=types[t][1];obj=default(t);index=-1
        while True:
            delta=r.uint()
            if delta==0:return obj
            index+=delta
            if index>=len(fields):raise DecodeError('Invalid Go gob field index')
            name,kind=fields[index];obj[name]=value(r,kind,depth+1)
    while r.pos<len(data):
        record=Reader(r.take(r.uint()));id=record.sint()
        if id<0:
            id=-id
            if not 65<=id<=4096 or id in types or len(types)>=16:raise DecodeError('Invalid Go gob type')
            record.expect(3);record.expect(1);record.expect(1);name=record.string();record.expect(1)
            if record.sint()!=id:raise DecodeError('Go gob type id mismatch')
            record.expect(0);record.expect(1);count=record.uint()
            if not 1<=count<=64:raise DecodeError('Invalid Go gob field count')
            fields=[]
            for _ in range(count):
                record.expect(1);field=record.string();record.expect(1);kind=record.sint();record.expect(0);fields.append((field,kind))
            record.expect(0);record.expect(0)
            types[id]=(name,fields)
        else:
            if result is not None or types[id][0]!='NativeConfig':raise DecodeError('Unexpected Go gob value')
            result=value(record,id)
        if record.pos!=len(record.data):raise DecodeError('Trailing Go gob message data')
    if result is None:raise DecodeError('No Go gob NativeConfig')
    return result

def linklayer(data):
    if not 355<=len(data)<=8388608 or data[:4]!=b'VER6':raise DecodeError('Unsupported LinkLayer version')
    def cipher(algorithm,key,record):
        n=algorithm.block_size
        return algorithm.new(key,algorithm.MODE_CFB,STATIC_IV[:n],segment_size=n*8).decrypt(record)
    stage=cipher(Blowfish,data[-8:],data[4:-8])
    if len(stage)<72:raise DecodeError('Truncated LinkLayer AES trailer')
    trailer=stage[-72:];key=trailer[:16]+trailer[-16:][::-1]
    stage=cipher(AES,key,stage[:-72])
    if len(stage)<76:raise DecodeError('Truncated LinkLayer Salsa container')
    packet=stage[32:-32][::-1]
    plain=packet[:8]+Salsa20.new(key=stage[:32],nonce=packet[:8]).decrypt(packet[8:])
    length=int.from_bytes(plain[8:12],'big')
    if length<75 or length*3!=len(plain)-12:raise DecodeError('Invalid LinkLayer CAST segment length')
    segment=plain[12+length:12+length*2]
    stage=cipher(CAST,segment[-16:],segment[:-16])
    if stage[0]==0:stage=stage[1:]
    elif stage[0]==1:
        stage=stage[1:];half=len(stage)//2;stage=stage[half:][::-1]+stage[:half]
    else:raise DecodeError('Invalid LinkLayer ordering flag')
    if len(stage)<58:raise DecodeError('Truncated LinkLayer inner record')
    stream=hashlib.pbkdf2_hmac('sha1',stage[:16],b'sH3CIVoF#rWLtJo6',32,1500)
    inner=bytearray(stage[16:])
    for i in range(min(1500,len(inner))):inner[i]^=stream[i]
    key=bytearray(inner[-32:]);key[0],key[-1]=key[-1],key[0]
    decoded=cipher(AES,bytes(key),bytes(inner[-42:-32])+bytes(inner[:-42])[::-1])
    return gob(decoded)
