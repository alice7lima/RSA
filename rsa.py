import numpy as np
import random
import hashlib
import math
import os
from random import randint
import struct

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

def rsa_decrypt(m, d, n):
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
    os.system('cls')
    p = prime_number()
    q = prime_number()
    # print(p)
    # print(q)
    n = p * q
    print("bitp:", p.bit_length())
    print("bitq: ", q.bit_length())
    print("bit: ", n.bit_length())
    e = ekey(p,q)
    #print("bacou")
    #print(e)
    aux = (p-1) * (q-1)
    d = dkey(e,aux)

    str2 = "a lice nao danca e nem grava tikoteko com o cralo, e o cralo fica muito triste com isso"
    
    r = os.urandom(32)
    result = OAEP_enc(str2, n, e, r)

    decript = OAEP_dec(result, n, d, r)

    print(decript)

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
    result = rsa_encrypt(e, n, result)

    return result


def OAEP_dec(m, n, d, r):
    global m_length, xl, yl
    k0 = len(r)
    nlen = 2048
    result = rsa_decrypt(m, d, n)
    result = result.to_bytes(xl+yl, byteorder='big')

    X = result[:xl]
    Y = result[xl:]

    r = byte_xor(Y, hashlib.sha3_256(X).digest())
    m = byte_xor(X, MGF(r, nlen - k0))

    m = str(m).replace("0", "")
    
    return m