import hashlib
import math
import rsa

def os2ip(x):
    return int.from_bytes(x, byteorder='big')

def i2osp(x, xlen):
    return x.to_bytes(xlen, byteorder='big')

def MGF(seed, mlen):
    t = b''
    hlen = len(hashlib.sha3_256().digest())
    for c in range(0, math.ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += hashlib.sha3_256(seed + _c).digest()
    return t[:mlen]

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def OAEP_enc(m,n,e,r):
    global m_length, xl, yl
    k0 = len(r)
    k1 = 128
    nlen = 2048

    for _ in range(k1):
        m += str(0)

    m_length = len(m)
    G = MGF(r, nlen - k0)
    X = byte_xor(bytes(m, "UTF-8"), G)
    Y = byte_xor(r, hashlib.sha3_256(X).digest())

    xl = len(X)
    yl = len(Y)

    result = b''.join([X, Y])

    result = int.from_bytes(result, byteorder='big')
    result = rsa.rsa_encrypt(e, n, result)
    print("RSA result:", result)

    return result


def OAEP_dec(m, n, d, r):
    global m_length, xl, yl
    k0 = len(r)
    nlen = 2048
    result = rsa.rsa_decrypt(m, d, n)
    result = result.to_bytes(xl+yl, byteorder='big')

    X = result[:xl]
    Y = result[xl:]

    r = byte_xor(Y, hashlib.sha3_256(X).digest())
    m = byte_xor(X, MGF(r, nlen - k0))

    m = str(m).replace("0", "")

    return m