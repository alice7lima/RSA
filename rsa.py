import numpy as np 
import random
import hashlib
import math
import os
from random import randint

'''
Metodo que aplica a funcao totiente de Euler em um numero
'''
def phi_euler(n):
    if(miller_rabin(n,40)):
        return (n-1)


'''
Funcao que verifica se um numero eh primo com base no teste de Miller Rabin
'''

def miller_rabin(n, k):

    if (n%2 == 0 or n < 2):
        return False

    if (n == 2):
        return True

    r = 0
    m = n-1

    while (m%2 == 0):
        r += 1
        m //= 2

    for i in range(k):
        a = random.randint(2, n-1)
        x = pow(a,m,n)

        if x == 1 or x == n-1:    
            continue

        for i in range(r-1):
            x = pow(x,2,n)
            if x == n-1:
                break
        else:
            return False

    return True

'''
    Funcao auxiliar que gera um numero primo
'''

def prime_number():
  n = random.getrandbits(1024)
  #print(n)

  while(miller_rabin(n, 40) == False):
    n = random.getrandbits(1024)

  return n

'''
    Funcao de crifragem do RSA  
'''

def rsa_encrypt(e, n, msg):
    return pow(msg, e, n)

'''
    Funcao de crifragem do RSA  
'''

def rsa_decrypt(m,d,n):
    return pow(m, d, n)


'''
    Funcao que descobre a chave publica E, para a cifragem.
'''


def ekey(p, q):
    eul = phi_euler(q)*phi_euler(p)
    e = random.randint(2, eul)
    
    while(np.gcd(eul, e) != 1):
        e = random.randint(2, eul)
    
    return e

'''
    Funcao que descobre a chave privada d, para a decifragem.
'''


def dkey(e, aux):
    u = [1,0,aux]
    v = [0,1,e]

    while(v[2] != 0):
        q = int(math.floor(u[2]//v[2]))
        a1 = u[0] - (q*v[0])
        a2 = u[1] - (q*v[1])
        a3 = u[2] - (q*v[2])
        u[0], u[1], u[2] = v[0], v[1], v[2]
        v[0], v[1], v[2] = a1, a2, a3

    if(u[1] < 0):
        return (u[1] + aux) 
    else:
        return (u[1]) 
    # for i in range(1, aux):
    #     if((e * i) % aux == 1):
    #         return i
    # print("nao encontrou")


def main_rsa():
    p = prime_number()
    q = prime_number()
    print("numeros: %d        %d" % (p, q))
    n = p * q
    e = ekey(p,q)
    print("e ", e)
    print("bacou")
    print(e)
    aux = (p-1) * (q-1)
    d = dkey(e,aux)

    str1 = "a lice nao danca com o cralo"
    str2 = hashlib.sha3_256(str1.encode())
    str2 = str2.hexdigest()
    # print(str2)
    r = os.urandom(64)

    c = OAEP_enc(str2, n, e, r)
    #print(c)
    print("############ Decripttt")
    OAEP_dec(c, n, d, r)



def i2osp(x, xlen):
    return x.to_bytes(xlen, byteorder='big')

def MGF(seed, mlen):
    t = b''
    hlen = 128
    for c in range(0, math.ceil(mlen / hlen)):
        _c = i2osp(c, 4)
        t += hashlib.sha3_256(seed + _c).digest()
    return t[:mlen]

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def OAEP_enc(m,n,e,r):
    k = math.ceil(n.bit_length()/8)
    mlen = len(m)
    k0 = int(math.ceil(len(r)/8))
    k1 = k-2*k0-mlen-2
    if k1 < 0:
        return False

    lhash = hashlib.sha3_256().hexdigest()
    hlen = len(lhash)/2

    ps = []
    while len(ps) != 2 * k1:
        ps.append('0')

    ps = ''.join(ps)

    pad = int(lhash + ps + '01' + m, 16)
    
    mask = int.from_bytes(MGF(r, k0 + k1 + mlen + 1),  byteorder='big')
    mask1 = mask ^ pad
    mask1 = mask1.to_bytes(mask1.bit_length()//8, byteorder='big')
    seedmask = MGF(mask1, k0)
    maskedseed = byte_xor(seedmask,r)

    res = b'\x00' + maskedseed + mask1
    res = int.from_bytes(res, byteorder='big')

    cripto = rsa_encrypt(e, n, res)

    return cripto


def OAEP_dec(m, n, d, r):
    mlen = math.ceil(m.bit_length()/8)
    dlen = math.ceil(d.bit_length()/8)
    print(mlen)
    print(dlen)

    k = math.ceil(n.bit_length()/8)
    k0 = int(math.ceil(len(r)/8))
    mlen = math.ceil(m.bit_length()/8)
    k1 = k - 2 * k0 - mlen - 2
    decript = rsa_decrypt(m, d, n)
    print(decript)

    p1 = (pow(2, 8 * (k0 + k1 + mlen + 1)) - 1) & decript
    p2 = (pow(2, 8 * k0) - 1) & (decript >> 8 * (k0 + k1 + mlen + 1))
    p3 = p1.to_bytes((p1.bit_length()//8) + 1, byteorder='big')
    p4 = int.from_bytes(MGF(p3, k0 + k1 + mlen + 1),  byteorder='big') ^ p2

    print("###### DEBUG")
    r = int.from_bytes(r, byteorder='big')
    if(r == p4):
        print("deu certo")
