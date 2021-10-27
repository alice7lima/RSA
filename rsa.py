import numpy as np
import random
import math
import hashlib
import os
import oaep
import impbase64

'''
Metodo que aplica a funcao totiente de Euler em um numero
'''
def phi_euler(n):                   #todos os numeros que utilizarao essa funcao precisam ser primos
    if(miller_rabin(n,40)):         #verifica se o numero eh primo com miller rabin 
        return (n-1)                #retorna (n-1), numero de coprimos menos ou iguais a n


'''
Funcao que verifica se um numero eh primo com base no teste de Miller Rabin
'''

def miller_rabin(n, k):

    if (n%2 == 0 or n < 2):                 #se eh um numero menor que 2 entao nao eh primo
        return False

    if (n == 2):                            #se for o numero 2, entao eh primo
        return True

    r = 0                                   #contador auxiliar r 
    m = n-1                                 #variavel auxiliar com n-1

    while (m%2 == 0):               
        r += 1                              #conta quantas sao as divisoes inteiras de m por 2
        m //= 2

    for i in range(k):                      #o teste eh realizado 40 vezes (k vezes)
        a = random.randint(2, n-1)          #eh utilizado um aleatorio a entre 2 e n-1
        x = pow(a,m,n)                      #a elevado a m mod n

        if x == 1 or x == n-1:              #se o resto de a na m por n for um ou n-1 realiza-se a proxima iteracao
            continue

        for i in range(r-1):                #caso contrario sao realizadas r-1 iteracoes (se r maior que 0)
            x = pow(x,2,n)                  #x eh atualizado com x elevado a 2 mod n 
            if x == n-1:                    #se x eh igual a n-1 entao n eh primo
                break                       #encerra o loop e vai para a proxima iteracao
        else:
            return False                    #se r-1 eh zero, entao n nao eh primo

    return True

'''
    Funcao auxiliar que gera um numero primo
'''

def prime_number():
  n = random.getrandbits(1024)                #geracao de um numero de 1024 bits

  while(miller_rabin(n, 40) == False):        #verifica se o n gerado eh primo
    n = random.getrandbits(1024)              #em caso negativo eh gerado um novo numero de 1024 bits 

  return n

'''
    Funcao de crifragem do RSA
'''

def rsa_encrypt(e, n, msg):                     
    return pow(msg, e, n)                       #faz msg elevado a e mod n

'''
    Funcao de crifragem do RSA
'''

def rsa_decrypt(m, d, n):
    return pow(m, d, n)                         #faz m elevado a d mod n


'''
    Funcao que descobre a chave publica E, para a cifragem.
'''

def ekey(p, q):                             
    eul = phi_euler(q)*phi_euler(p)             #aplica a funcao totiente de Euler em p*q
    e = random.randint(2, eul)                  #gera um inteiro aleatorio entre 2 e totiente de Euler de p*q

    while(np.gcd(eul, e) != 1):                 #verifica se o mdc de eul com e eh diferente de 1
        e = random.randint(2, eul)              #em caso positivo eh escolhido outro e 

    return e                                    #caso o mdc de e com eul seja um este eh escolhido como chave

'''
    Funcao que descobre a chave privada d, para a decifragem.
'''

def dkey(e, phi):
    #vetores auxiliares
    u = [1,0,phi]                   
    v = [0,1,e]

    while(v[2] != 0):                                 # enquanto a posicao do vetor que inicialmente guarda e eh maior que zero
        q = int(math.floor(u[2]//v[2]))               # eh calculado o chao da divisao de u por v (inicialmente phi/e)
        a1 = u[0] - (q*v[0])                          # calculo dos novos valores do vetor v  
        a2 = u[1] - (q*v[1])
        a3 = u[2] - (q*v[2])        
        u[0], u[1], u[2] = v[0], v[1], v[2]           # transfere os valores do vetor v para o vetor u
        v[0], v[1], v[2] = a1, a2, a3                 # atualiza os valores de v

    if(u[1] < 0):                                     # se a primeira posicao de u eh negativa entao d eh phi - u[1]
        return (u[1] + phi)
    else:
        return (u[1])                                 # se eh positiva entao eh o proprio d

'''
Funcao que gera a assinatura da mensagem cifrada.
O hash da mensagem original eh gerado e este eh cifrado junto a chave privada d
'''
def signature(m,d,n):
    hashed = hashlib.sha3_256(m.encode('ascii')).digest()           # faz o hash da mensagem
    hashed = oaep.os2ip(hashed)                                     # coverte para um inteiro
    s = rsa_decrypt(hashed,d,n)                                     # eh feito a cifragem com rsa da mensagem com a chave privada                                     
    print("Assinatura gerada em bits: %s\n\n" % oaep.i2osp(s, 256))
    return s


'''
Funcao que compara o hash da mensagem decriptada com o hash derivado da assinatura.
'''
def verification(m,s,n,e):
    hashed = hashlib.sha3_256(m.encode('ascii')).digest()          # faz o hash da mensagem decriptada
    s = oaep.i2osp(s, 256)                                         # converte a assinatura para um inteiro
    s = oaep.os2ip(s)
                                       
    v = rsa_encrypt(e,n,s)                                         # eh feito a cifracao com rsa da assinatura com a chave privada
    v = oaep.i2osp(v,32)                                           # resultado eh convertido para sequencia de bytes

    if(hashed == v):                                                # verifica se o hash da mensagem decriptada eh igual a assinatura decifrada
        return True                                                 # em caso positivo a assinatura eh valida
    else:
        return False                                                # em caso negativo a assinatura eh invalida

'''
    Funcao corrente que executa toda a cifragem e decifragem do do rsa com a dinamica OAEP.
'''
def main_rsa():
    inp = input()
    
    #gera dois numeros de 1024 bits primos
    print("Gerando P e Q...")
    p = prime_number()                              
    q = prime_number()

    n = p * q                                           # gera o primeiro numeoro da chave publica
    e = ekey(p,q)                                       # gera o segundo numero da chave publica

    print("Chave publica gerada")

    aux = phi_euler(p)*phi_euler(q)
    d = dkey(e,aux)

    print("Chave privada gerada")

    f = open("resultados.txt", "w+")

    r = os.urandom(32)                                  # gera r aleatoriamente

    s = signature(inp,d,n)                              # gera a assinatura 
    s_str = str(s)
    s_crp = impbase64.encode64(s_str)


    result_cifra = oaep.OAEP_enc(inp, n, e, r)          # cifra a mensagem
    men_cifrada = str(result_cifra)
    print("Resultado da cifragem: %s\n\n" % men_cifrada)
    result = impbase64.encode64(men_cifrada)

    f.write("Assinatura em Base 64:\n%s\n\n" % s_crp)               # resultados impressos no arquivo de texto
    f.write("Mensagem cifrada em base 64:\n%s\n\n" % result)
    f.write("Chave Publica n: %s\n" % impbase64.encode64(str(n)))
    f.write("Chave Publica e: %s\n" % impbase64.encode64(str(e)))

    men_decifrada = impbase64.decode64(result)
    aux = men_cifrada.encode('ascii')
    men_decifrada = int(aux, 10)
    decript = oaep.OAEP_dec(men_decifrada, n, d, r)         # decifra a mensagem
    decript = decript[2:len(decript)-1]
    print("Resultado da decifragem: %s\n" % decript)

    s_dec = impbase64.decode64(s_crp)
    s_dec_asc = s_dec.encode('ascii')
    s_dec_str = str(s_dec_asc)
    s_dec_int = s_dec_str[2:len(s_dec_str)-5]
    s_dec_int = s_dec_int.encode('ascii')
    s_dec_int = int(s_dec_int, 10)

    if(verification(decript,s_dec_int,n,e) == True):         # verifica se a assinatura eh valida
        print("Verificado: assinatura valida")
    else:
        print("Erro: assinatura invalida")
