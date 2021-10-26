import hashlib
import math
import rsa

''' 
    Funcao converte um conjunto de bytes para inteiro.
'''
def os2ip(x):
    return int.from_bytes(x, byteorder='big')

'''
    Funcao que converte um inteiro para um conjunto de bytes especificado no parametro da funcao.
    Obs: Certifique-se de que o inteiro sempre cabera no conjunto de bytes especificado.
'''
def i2osp(x, xlen):
    return x.to_bytes(xlen, byteorder='big')

'''
    Funcao que faz a geracao de mascara de bits de um tamanho desejado.
    Recebe uma string de octeto e um comprimento de saída.
'''
def MGF(seed, mlen):
    t = b''
    hlen = len(hashlib.sha3_256().digest())        # Quantidade de bytes do hash utilizado.
    for c in range(0, math.ceil(mlen / hlen)):     # Loop para a concatenacao de octetos de acordo com o tamanho da mensagem e do hash escolhido.
        _c = i2osp(c, 4)                           # Reune o contador da mascara em octetos.
        t += hashlib.sha3_256(seed + _c).digest()  # Faz o hash do octeto gerado com a seed de qual a mascara eh gerada e concatena formando uma nova string de bytes.
    return t[:mlen]

'''
    Funcao que faz a operacao de xor com uma string de bytes.
'''
def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

'''
    Funcao que faz a cifragem do rsa com o esquema OAEP.
    Recebe como parametro a mesagem, o tamanho do modulo rsa utilizado, a chave publica 'e' e a string randomica 'r'.
'''
def OAEP_enc(m, n, e, r):
    global m_length, xl, yl
    k0 = len(r)                                          # k0: tamanho da chave randomica gerada.
    k1 = 32                                              # k1: 32 bits por padrao
    nlen = 2048                                          # nlen o tamanho em bits do modulo rsa, no caso 2048.

    # Mensagem inicialmente possui tamanho (nlen-k0-k1) bits.

    for _ in range(k1):         # Faz o padding de 0s na mensagem, ja que a mensagem precisa ser do tamanho n-k0.
        m += str(0)

    m_length = len(m)
    G = MGF(r, nlen - k0)                           # Aplica a mascara de bytes na string randomica 'r' no tamanho de n-k0
    X = byte_xor(bytes(m, "UTF-8"), G)              # Faz o xor byte a byte da mensagem com a mascara geraada anteriormente.
    Y = byte_xor(r, hashlib.sha3_256(X).digest())   # Faz o xor de 'r' com a reducao de bytes aplicado em X.

    xl = len(X)
    yl = len(Y)

    result = b''.join([X, Y])                      # A saida do oaep sera a concatenacao desses dois blocos, o X e o Y.

    result = int.from_bytes(result, byteorder='big')    # Transforma o conjunto de bytes para inteiro.
    result = rsa.rsa_encrypt(e, n, result)              # Faz a cifragem desses inteiros.
    # print("RSA result:", result)

    return result

'''
    Funcao que faz a decifragem do rsa com o esquema OAEP.
    Recebe como parametro a mesagem, o tamanho do modulo rsa utilizado, a chave privada 'd' e a string randomica 'r'.
'''
def OAEP_dec(m, n, d, r):
    global m_length, xl, yl
    k0 = len(r)                   # k0: tamanho da chave randomica gerada.  
    nlen = 2048                   # hlen o tamanho em bits do modulo rsa, no caso 2048.

    result = rsa.rsa_decrypt(m, d, n)   # Aplica a decifragem do rsa.
    result = result.to_bytes(xl+yl, byteorder='big') # Converte para bits de acordo com o tamanho dos blocos cifrados.

    X = result[:xl]               # Separa os blocos de acordo com o tamanho da mensagem que foi cifrada. 
    Y = result[xl:]              

    raux = byte_xor(Y, hashlib.sha3_256(X).digest())   # Recuperacao do 'r' na mensagem cifrada.

    if(r != raux):                                     # Verificacao se o 'r' eh o mesmo gerado na cifragem.
        print("r nao encontrado na mensagem cifrada.")
        return False
    
    m = byte_xor(X, MGF(r, nlen - k0))                 # Recuperacao da mensagem depois da descoberta do 'r'.

    m = str(m).replace("0", "") # Retira o padding da mensagem

    return m