import string

from numpy import character
base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def encode64(m):
    result = ''
    if(len(m) % 3 != 0):
        pad = 3 - (len(m) % 3)
    
    binary_converted = ("".join(f"{ord(i):08b}" for i in m))
    padding = binary_converted + ('0' * pad*2)

    for i in range(0, len(padding), 6):
        aux = padding[i:i+6]
        result += base64[int(aux,2)]

    for _ in range(pad):
        result += '='

    return result

def decode64(s):
    result = ''
    if s[-2:] == '==':
        pad = 2
    elif s[-1:] == '=':
        pad = 1
    else:
        pad = 0
    
    s = s[:-pad]
    binary_converted = ("".join(f"{base64.find(i):06b}" for i in s))
    
    for i in range(0, len(binary_converted), 8):
        aux = binary_converted[i:i+8]
        result += chr(int(aux, 2))

    return result


# if __name__ == '__main__':
#     s = input()
#     output = encode64(s)
#     print(output)
#     print(decode64(output))
