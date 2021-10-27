import string
from numpy import character

base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/" # String que contem todos os caracteres da base64

'''
    Funcao para fazer a codificacao para a base64.
'''

def encode64(m):
    result = ''
    pad = 0
    if(len(m) % 3 != 0):                    # Verifica o tamanho da mensagem para adicionar um padding se necessario,
        pad = 3 - (len(m) % 3)              # adicionado se caso nao for multiplo de 3.
    
    binary_converted = ("".join(f"{ord(i):08b}" for i in m))      # Conversao dos caracteres para binario de 8 bits.
    padding = binary_converted + ('0' * pad*2)

    for i in range(0, len(padding), 6):           # Checa de 6 em 6 bits para converte-los em um novo caractere de acordo com a string base64
        aux = padding[i:i+6]
        result += base64[int(aux,2)]

    for _ in range(pad):                    # Adiciona o caractere '=' caso a mensagem seja multiplo de 3.
        result += '='                       # Para a identificacao de preenchimento.

    return result

'''
    Funcao para fazer a descodificacao de uma mensagem em base64.
'''

def decode64(m):
    result = ''
    pad = 0
    if m[-2:] == '==':                   # Verifica a existencia de preenchimento na mensagem.
        pad = 2
    elif m[-1:] == '=':
        pad = 1
    else:
        pad = 0
    
    m = m[:-pad]
    binary_converted = ("".join(f"{base64.find(i):06b}" for i in m))    # Converte para binario de 6 bits de acordo com o indice na string base64.
    
    for i in range(0, len(binary_converted), 8):        # Seleciona de 8 em 8 bits para a conversao de acordo com a tabela ascii.
        aux = binary_converted[i:i+8]
        result += chr(int(aux, 2))

    return result


# if __name__ == '__main__':
#     s = input()
#     output = encode64(s)
#     print(output)
#     print(decode64(output))
