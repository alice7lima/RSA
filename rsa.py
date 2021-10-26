import numpy as np
import random
import math
import hashlib
import os
import oaep

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

'''
Funcao que gera a assinatura da mensagem cifrada.
O hash da mensagem original eh gerado e este eh cifrado junto a chave privada d
'''
def signature(m,d,n):
    hashed = hashlib.sha3_256(m.encode('ascii')).digest()
    hashed = oaep.os2ip(hashed)
    #s = rsa_decrypt(hashed,d,n)
    s = rsa_encrypt(d,n,hashed)
    aux = oaep.i2osp(s,256)
    return aux


'''
Funcao que compara o hash da mensagem decriptada com o hash derivado da assinatura.
'''
def verification(m,s,n,e):
    hashed = hashlib.sha3_256(m.encode('ascii')).digest()
    s = oaep.os2ip(s)
    v = rsa_decrypt(s,e,n)
    v = oaep.i2osp(v,32)

    if(hashed == v):
        return True
    else:
        return False

'''
    Funcao corrente que executa toda a cifragem e decifragem do do rsa com a dinamica OAEP.
'''
def main_rsa():
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

    str2 = "a lice danca e e e e nem grava tikoteko com o cralo, e o cralo fica muito triste com isso."
    r = os.urandom(32)

    result = oaep.OAEP_enc(str2, n, e, r)
    decript = oaep.OAEP_dec(result, n, d, r)

    print("Resultado decript:", decript)
    s = signature(str2,e,n)

    print("assinature", verification(str2,s,n,d))