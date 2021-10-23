from math import sqrt
import numpy as np 
import random
from random import randint

'''
Metodo que aplica a funcao totiente de Euler em um numero
'''
def phi_euler(n):
    if(miller_rabin(n)):
        return (phi_euler-1)


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
    Funcao que descobre a chave publica E, para a cifragem.
'''

def ekey(n):
    e = random.randInt(1, n)
    
    while(np.gcd(n, e) == 1):
        e = random.randInt(1, n)
    
    return e

'''
    Funcao que descobre a chave privada d, para a decifragem.
'''

def dkey(e, n):
    d = 1
    while((d*e)% n == 1):
        d+=1

    return d


def get_public_key():
    p = prime_number()
    q = prime_number()

    #e = ekey(n)
    #d = dkey(e, n)

    print("numeros: %d        %d" % (p, q))