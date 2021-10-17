from math import sqrt
import numpy as np 
import random

'''
Metodo que aplica a funcao totiente de Euler em um numero
'''
def phi_euler(n):
    if(check_prime(n)):
        return (phi_euler-1)


'''
Funcao que verifica se um numero eh primo com base no teste de Miller Rabin
'''

def check_prime(n):
    nmu = n-1
    k = 0
    i = 1
    m = 0
    while(nmu%(pow(2,i)) == 0):
        m = nmu%(pow(2,i))
        i += 1
        k += 1

    a = random.randrange(2,n-2)

    if((pow(a,m) % n) == 1 or -(pow(a,m) % n) == 1):
        return True
    else:
        b = pow(a,m)
        while(1):
            if(b*b % n == 1):
                return False
            elif(-(b*b) % n == 1):
                return True
            else:
                b = b*b % n 


'''
    Funcao auxiliar que gera um numero primo
'''

def prime_number():
    n = random.getrandbits(1024)

    while(not check_prime(n)):
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