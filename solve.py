import struct

real_flag = open('flag.txt').read().strip()
assert len(real_flag) == 32

flag = real_flag + '\0'*20

def add8(a, b):
    a, = struct.unpack('<Q', a)
    b, = struct.unpack('<Q', b)
    return struct.pack('<Q', (a+b)%2**64)

def sub8(a, b):
    a, = struct.unpack('<Q', a)
    b, = struct.unpack('<Q', b)
    return struct.pack('<Q', (a-b)%2**64)

add = '\x5f\x38\x01\0\0\0\0\0'

for i in range(0,len(real_flag),3):
    flag = flag[:i] + add8(flag[i:i+8], add) + flag[i+8:]
flag = flag[:32]

def tohex(s):
    if isinstance(s, (str,unicode,bytes)):
        s = map(ord,s)
    return ' '.join('%02x' % x for x in s)

print 'Flag after encryption in SPC700:', tohex(flag)

mask64 = (1<<64)-1

key1 = 0x33c300133700c4fe
key2 = 0xb4be00d34d00c0d3
key = struct.pack('<QQ', key2, key1)
rounds = 42

def rol64(val, w):
    return ((val << w)  | (val >> (64-w)))&mask64

def ror64(val, w):
    return ((val >> w)  | (val << (64-w)))&mask64

def xor(a, b):
    assert len(a) == len(b)
    return ''.join(chr(ord(x)^ord(y)) for x, y in zip(a,b))

def round(a0, a1, b0, b1):
    a = struct.pack('<QQ', a0, a1)
    b = struct.pack('<QQ', b0, b1)
    def check():
        aa = struct.pack('<QQ', a0, a1)
        bb = struct.pack('<QQ', b0, b1)
        # print '============'
        # print tohex(a)
        # print tohex(aa)
        assert a == aa
        assert b == bb

    a, b = a[8:16] + b[8:16], b[0:8] + a[0:8]
    a0, a1, b0, b1 = a1, b1, b0, a0
    check()
    # print "a=",a0, a1, b0, b1

    a = a[2:4] + a[6:8] + a[0:2] + a[4:6] + a[8:16]
    b = b[2:4] + b[4:6] + b[6:8] + b[0:2] + b[8:16]

    a0_ = 0
    for i, x in enumerate([1,3,0,2]):
        a0_ |= ((a0 >> x*16) & 0xffff) << (i*16)
    a0=a0_
    b0_ = 0
    for i, x in enumerate([1,2,3,0]):
        b0_ |= ((b0 >> x*16) & 0xffff) << (i*16)
    b0=b0_
    check()
    # print "b=",a0, a1, b0, b1

    a = a[0:8] + a[12:14] + a[8:10] + a[10:12] + a[14:16]
    b = b[0:8] + b[14:16] + b[10:12] + b[8:10] + b[12:14]

    a1_ = 0
    for i, x in enumerate([2,0,1,3]):
        a1_ |= ((a1 >> x*16) & 0xffff) << (i*16)
    a1=a1_
    b1_ = 0
    for i, x in enumerate([3,1,0,2]):
        b1_ |= ((b1 >> x*16) & 0xffff) << (i*16)
    b1=b1_
    check()
    # print "c=",a0, a1, b0, b1

    a0_, a1_ = struct.unpack('<QQ', a)
    b0_, b1_ = struct.unpack('<QQ', b)
    a0_, a1_ = rol64(a0_, 13), rol64(a1_, 13)
    b0_, b1_ = ror64(b0_, 17), ror64(b1_, 17)
    a = struct.pack('<QQ', a0_, a1_)
    b = struct.pack('<QQ', b0_, b1_)

    a0, a1 = rol64(a0, 13), rol64(a1, 13)
    b0, b1 = ror64(b0, 17), ror64(b1, 17)
    check()
    # print "d=",a0, a1, b0, b1

    a = xor(a, key)
    b = xor(b, key)

    a0 = a0 ^ key2
    a1 = a1 ^ key1
    b0 = b0 ^ key2
    b1 = b1 ^ key1
    check()
    # print "e=",a0, a1, b0, b1
    return a0,a1,b0,b1

def round_rev(a0, a1, b0, b1):
    a0 = a0 ^ key2
    a1 = a1 ^ key1
    b0 = b0 ^ key2
    b1 = b1 ^ key1
    # print "d=",a0,a1,b0,b1

    a0, a1 = ror64(a0, 13), ror64(a1, 13)
    b0, b1 = rol64(b0, 17), rol64(b1, 17)
    # print "c=",a0,a1,b0,b1

    a1_ = 0
    for i, x in enumerate([1,2,0,3]):
        a1_ |= ((a1 >> x*16) & 0xffff) << (i*16)
    a1=a1_
    b1_ = 0
    for i, x in enumerate([2,1,3,0]):
        b1_ |= ((b1 >> x*16) & 0xffff) << (i*16)
    b1=b1_
    # print "b=",a0,a1,b0,b1

    a0_ = 0
    for i, x in enumerate([2,0,3,1]):
        a0_ |= ((a0 >> x*16) & 0xffff) << (i*16)
    a0=a0_
    b0_ = 0
    for i, x in enumerate([3,0,1,2]):
        b0_ |= ((b0 >> x*16) & 0xffff) << (i*16)
    b0=b0_
    # print a0,a1,b0,b1

    a0, a1, b0, b1 = b1, a0, b0, a1
    return a0,a1,b0,b1

a0, a1, b0, b1 = struct.unpack('<QQQQ', flag)

for _ in range(rounds):
    old = a0,a1,b0,b1
    a0,a1,b0,b1=round(a0,a1,b0,b1)
    assert round_rev(a0,a1,b0,b1) == old

print "constants="
print "a1=",hex(a1)
print "a0=",hex(a0)
print "b1=",hex(b1)
print "b0=",hex(b0)

for _ in range(rounds):
    a0,a1,b0,b1=round_rev(a0,a1,b0,b1)

flag2 = struct.pack('<QQQQ', a0,a1,b0,b1)
assert flag2 == flag

flag2 += '\0'*32
for i in reversed(list(range(0,len(real_flag),3))):
    flag2 = flag2[:i] + sub8(flag2[i:i+8], add) + flag2[i+8:]

flag2 = flag2[:32]
print 'Solution:', flag2[:32]
assert flag2 == real_flag
