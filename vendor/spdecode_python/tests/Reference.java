import java.nio.*;import java.nio.file.*;import java.util.*;
public class Reference {
 static byte[] block=new byte[16];
 static String hex(byte[] b){StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format("%02x",x&255));return s.toString();}
 public static void main(String[] args)throws Exception{
 for(int i=0;i<16;i++)block[i]=(byte)(i*13+7);
 U u=new U(Files.readAllBytes(Path.of(args[0],"npvs_v5_tables.bin")));
 int[] state=new int[16];for(int i=0;i<16;i++)state[i]=block[i]&255;
 for(int r=0;r<u.f4572c;r++){int[] p=new int[16];for(int i=0;i<16;i++)p[i]=state[u.f4571b[i]];state=u.a(r,u.f4575f,u.a(r,u.f4573d,p));}
 byte[] result=new byte[16];for(int i=0;i<16;i++)result[i]=u.f4570a[u.f4574e+i*256+state[u.f4571b[i]]];
 System.out.println("npvs "+hex(result));
 NPV npv=new NPV(Files.readAllBytes(Path.of(args[0],"npv_whitebox.bin")));
 int[] p=new int[16];for(int i=0;i<16;i++)p[i]=block[u.f4571b[i]]&255;
 p=npv.o(npv.o(p,npv.a),npv.b);for(int i=0;i<16;i++)result[i]=npv.last[i*256+p[u.f4571b[i]]];
 System.out.println("npv "+hex(result));
 byte[] words=new byte[64],key=new byte[32];for(int i=0;i<64;i++)words[i]=(byte)(i*7+11);for(int i=0;i<32;i++)key[i]=(byte)(i*19+3);
 System.out.println("threefishBefore "+hex(R.r(words,key,false,(i,w)->new long[]{(Integer)i,64L*(Integer)i})));
 System.out.println("threefishAfter "+hex(R.r(words,key,true,(i,w)->new long[]{(Integer)i,64L*(Integer)i})));
 }
}
interface Tweak {Object j(Object i,Object words);}
class k2 {static class j {static void e(Object v,String m){}static void d(Object v,String m){}}}
class K0 {static class m {static int B(int start,int end,int step){return end-((end-start)%step);}}}
class W1 {static class l {
 static byte[] h0(byte[] b,int s,int e){return Arrays.copyOfRange(b,s,e);}
 static void f0(long[] a,long[] b,int p,int f){System.arraycopy(a,0,b,p,a.length);}
 static void d0(int pos,int s,int f,byte[] a,byte[] b){System.arraycopy(a,s,b,pos,a.length-s);}
}}
class NPV {
 Object f4490k; int[] a=new int[4096],b=new int[4096];byte[] last;
 NPV(byte[] raw){ByteBuffer p=ByteBuffer.wrap(raw).order(ByteOrder.BIG_ENDIAN);p.position(8);byte[] xor=new byte[24576];p.get(xor);f4490k=xor;for(int i=0;i<4096;i++)a[i]=p.getInt();for(int i=0;i<4096;i++)b[i]=p.getInt();last=new byte[4096];p.get(last);}
    public int[] o(int[] iArr, int[] iArr2) {
        int[] iArr3 = new int[16];
        int i3 = 0;
        for (int i4 = 0; i4 < 4; i4++) {
            int i5 = i4 * 4;
            int[] iArr4 = new int[4];
            for (int i6 = i3; i6 < 4; i6++) {
                int i7 = i5 + i6;
                iArr4[i6] = iArr2[(i7 * 256) + iArr[i7]];
            }
            int i8 = i3;
            while (i8 < 4) {
                int i9 = (i8 * 6) + (i4 * 24);
                int i10 = i8 * 8;
                int i11 = 28 - i10;
                int i12 = 24 - i10;
                int i13 = i3;
                iArr3[i5 + i8] = (d(i9 + 4, d(i9, (iArr4[i3] >>> i11) & 15, (iArr4[1] >>> i11) & 15), d(i9 + 1, (iArr4[2] >>> i11) & 15, (iArr4[3] >>> i11) & 15)) << 4) | d(i9 + 5, d(i9 + 2, (iArr4[i13] >>> i12) & 15, (iArr4[1] >>> i12) & 15), d(i9 + 3, (iArr4[2] >>> i12) & 15, (iArr4[3] >>> i12) & 15));
                i8++;
                i3 = i13;
            }
        }
        return iArr3;
    }    public int d(int i3, int i4, int i5) {
        return ((byte[]) this.f4490k)[(i3 * 256) + (i4 << 4) + i5] & 15;
    }
}
class R {
 static int[][] f4612c={{14,16},{52,57},{23,40},{5,37},{25,33},{46,12},{58,22},{32,32}};
 static int[] f4613d={0,3,2,1};
    public static byte[] r(byte[] bArr, byte[] bArr2, boolean z3, Tweak eVar) {
        int i3;
        int i4;
        long[] jArr;
        int i5;
        byte[] bArr3 = bArr;
        int i6 = 4;
        int i7 = 5;
        int i8 = 0;
        int i9 = 2;
        int i10 = 3;
        k2.j.e(bArr2, "key");
        if (bArr2.length < 32 || bArr3.length > 2097152 || bArr3.length == 0 || bArr3.length % 32 != 0) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        byte[] bArrCopyOf = Arrays.copyOf(bArr2, 32);
        k2.j.d(bArrCopyOf, "copyOf(...)");
        long[] jArrM = m(bArrCopyOf);
        byte[] bArr4 = new byte[bArr3.length];
        int iB = K0.m.B(0, bArr3.length - 1, 32);
        if (iB >= 0) {
            int i11 = 0;
            while (true) {
                int i12 = i11 + 32;
                long[] jArrM2 = m(W1.l.h0(bArr3, i11, i12));
                int i13 = i8;
                long[] jArr2 = (long[]) eVar.j(Integer.valueOf(i11 / 32), jArrM2);
                if (jArr2.length != i9) {
                    throw new IllegalArgumentException("Failed requirement.");
                }
                long[] jArrCopyOf = Arrays.copyOf(jArrM, i7);
                k2.j.d(jArrCopyOf, "copyOf(...)");
                jArrCopyOf[i6] = (((jArrCopyOf[i13] ^ 2004413935125273122L) ^ jArrCopyOf[1]) ^ jArrCopyOf[i9]) ^ jArrCopyOf[i10];
                long j3 = jArr2[i13];
                long j4 = jArr2[1];
                long[] jArr3 = new long[i10];
                jArr3[i13] = j3;
                jArr3[1] = j4;
                jArr3[i9] = j3 ^ j4;
                int i14 = i7;
                int i15 = i9;
                long[][] jArr4 = new long[19][];
                int i16 = i10;
                int i17 = i13;
                for (int i18 = 19; i17 < i18; i18 = 19) {
                    long j5 = jArrCopyOf[i17 % 5];
                    int i19 = i17 + 1;
                    long j6 = jArrCopyOf[i19 % 5] + jArr3[i17 % 3];
                    long j7 = jArrCopyOf[(i17 + 2) % 5] + jArr3[i19 % 3];
                    long j8 = jArrCopyOf[(i17 + 3) % 5] + i17;
                    long[] jArr5 = new long[i6];
                    jArr5[i13] = j5;
                    jArr5[1] = j6;
                    jArr5[i15] = j7;
                    jArr5[i16] = j8;
                    jArr4[i17] = jArr5;
                    i17 = i19;
                }
                long[] jArr6 = (long[]) jArrM2.clone();
                int i20 = 17;
                while (-1 < i20) {
                    long[] jArr7 = jArr4[i20 + 1];
                    for (int i21 = i13; i21 < i6; i21++) {
                        jArr6[i21] = jArr6[i21] - jArr7[i21];
                    }
                    int i22 = i16;
                    int i23 = -1;
                    while (i23 < i22) {
                        int[] iArr = f4613d;
                        if (z3) {
                            i3 = i6;
                            i4 = i13;
                        } else {
                            long[] jArr8 = new long[i6];
                            for (int i24 = i13; i24 < i6; i24++) {
                                jArr8[i24] = jArr6[iArr[i24]];
                            }
                            i3 = i6;
                            i4 = i13;
                            W1.l.f0(jArr8, jArr6, i4, 14);
                        }
                        int[] iArr2 = f4612c[((i20 * 4) + i22) % 8];
                        int i25 = iArr2[i4];
                        long j9 = jArr6[i4];
                        int i26 = i4;
                        long[] jArr9 = jArr6;
                        long jRotateRight = Long.rotateRight(j9 ^ jArr6[1], i25);
                        jArr9[i26] = j9 - jRotateRight;
                        jArr9[1] = jRotateRight;
                        int i27 = iArr2[1];
                        long j10 = jArr9[i15];
                        long[] jArr10 = jArrM;
                        long jRotateRight2 = Long.rotateRight(j10 ^ jArr9[i16], i27);
                        jArr9[i15] = j10 - jRotateRight2;
                        jArr9[i16] = jRotateRight2;
                        if (z3) {
                            int i28 = i3;
                            long[] jArr11 = new long[i28];
                            int i29 = 0;
                            while (i29 < i28) {
                                jArr11[i29] = jArr9[iArr[i29]];
                                i29++;
                                i28 = 4;
                            }
                            jArr = jArr9;
                            i5 = 0;
                            W1.l.f0(jArr11, jArr, 0, 14);
                        } else {
                            jArr = jArr9;
                            i5 = 0;
                        }
                        i22--;
                        i13 = i5;
                        jArrM = jArr10;
                        i23 = -1;
                        i6 = 4;
                        jArr6 = jArr;
                    }
                    i20--;
                    i6 = 4;
                    jArr6 = jArr6;
                }
                long[] jArr12 = jArr6;
                int i30 = i13;
                long[] jArr13 = jArrM;
                int i31 = i30;
                while (i31 < 4) {
                    jArr12[i31] = jArr12[i31] - jArr4[i30][i31];
                    i31++;
                    i30 = 0;
                }
                ByteBuffer byteBufferOrder = ByteBuffer.allocate(jArr12.length * 8).order(ByteOrder.LITTLE_ENDIAN);
                for (long j11 : jArr12) {
                    byteBufferOrder.putLong(j11);
                }
                byte[] bArrArray = byteBufferOrder.array();
                k2.j.d(bArrArray, "array(...)");
                W1.l.d0(i11, 0, 12, bArrArray, bArr4);
                if (i11 == iB) {
                    break;
                }
                i8 = 0;
                i6 = 4;
                bArr3 = bArr;
                jArrM = jArr13;
                i11 = i12;
                i7 = i14;
                i9 = i15;
                i10 = i16;
            }
        }
        return bArr4;
    }
    public static long[] m(byte[] bArr) {
        if (bArr.length % 8 != 0) {
            throw new IllegalArgumentException("Failed requirement.");
        }
        ByteBuffer byteBufferOrder = ByteBuffer.wrap(bArr).order(ByteOrder.LITTLE_ENDIAN);
        int length = bArr.length / 8;
        long[] jArr = new long[length];
        for (int i3 = 0; i3 < length; i3++) {
            jArr[i3] = byteBufferOrder.getLong();
        }
        return jArr;
    }
}


/* loaded from: classes.dex */
class U {

    /* renamed from: a, reason: collision with root package name */
    public final byte[] f4570a;

    /* renamed from: b, reason: collision with root package name */
    public final int[] f4571b = {0, 5, 10, 15, 4, 9, 14, 3, 8, 13, 2, 7, 12, 1, 6, 11};

    /* renamed from: c, reason: collision with root package name */
    public final int f4572c;

    /* renamed from: d, reason: collision with root package name */
    public final int f4573d;

    /* renamed from: e, reason: collision with root package name */
    public final int f4574e;

    /* renamed from: f, reason: collision with root package name */
    public final int f4575f;

    public U(byte[] bArr) {
        this.f4570a = bArr;
        int i3 = (bArr[0] & 255) - 1;
        this.f4572c = i3;
        int i4 = (i3 * 24576) + 1;
        this.f4573d = i4;
        int i5 = i3 * 16384;
        int i6 = i4 + i5;
        this.f4574e = i6;
        int i7 = i6 + 4096;
        this.f4575f = i7;
        if (i3 != 13 || i5 + i7 != bArr.length) {
            throw new IllegalArgumentException("Failed requirement.");
        }
    }

    public static final int b(U u3, int i3, int[] iArr, int i4, int i5, int i6, int i7) {
        return u3.f4570a[(((iArr[i5] >>> i7) & 15) * 16) + (i4 * 256) + i3 + ((iArr[i6] >>> i7) & 15)] & 255;
    }

    public final int[] a(int i3, int i4, int[] iArr) {
        byte[] bArr;
        int[] iArr2 = new int[16];
        for (int i5 = 0; i5 < 4; i5++) {
            int[] iArr3 = new int[4];
            U u3 = this;
            int i6 = 0;
            while (true) {
                bArr = u3.f4570a;
                if (i6 >= 4) {
                    break;
                }
                int i7 = (i5 * 4) + i6;
                int i8 = (iArr[i7] * 4) + (i7 * 1024) + (i3 * 16384) + i4;
                iArr3[i6] = (bArr[i8 + 3] & 255) | ((bArr[i8] & 255) << 24) | ((bArr[i8 + 1] & 255) << 16) | ((bArr[i8 + 2] & 255) << 8);
                i6++;
            }
            int i9 = 0;
            while (i9 < 4) {
                int i10 = (i3 * 24576) + 1 + (((i9 * 6) + (i5 * 24)) * 256);
                int i11 = i9 * 8;
                int i12 = 28 - i11;
                int i13 = bArr[i10 + 1024 + (b(u3, i10, iArr3, 0, 0, 1, i12) * 16) + b(this, i10, iArr3, 1, 2, 3, i12)] & 255;
                int i14 = 24 - i11;
                iArr2[(i5 * 4) + i9] = (bArr[(b(this, i10, iArr3, 2, 0, 1, i14) * 16) + i10 + 1280 + b(this, i10, iArr3, 3, 2, 3, i14)] & 255) | (i13 << 4);
                i9++;
                u3 = this;
            }
        }
        return iArr2;
    }
}
