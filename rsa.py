from math import sqrt
import random

'''
Metodo que aplica a funcao totiente de Euler em um numero
'''
def phi_euler(n):
    if(check_prime(n)):
        return (phi_euler-1)


'''
Funcao que verifica se um numero eh primo
'''

def check_prime(n):
    if n < 2:
        return False
    else:
        for i in range(2, int(sqrt(n))+1):
            if(n%i == 0):
                return False
        return True       


# '''
# Funcao auxiliar que gera um numero primo
# '''

# def prime_number():
#     n = random.randrange(1,500)

#     while (not check_prime(n)):
#         n = random.randrange(1,500)

#     return n
