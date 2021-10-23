import rsa

while(1):
    print("MENU", end="\n")

    print("1 - Cifrar com RSA", end='\n')
    print("2 - Decifrar com RSA", end='\n')
    print("0 - Sair", end='\n')
    op = int(input("Escolha uma opcao: "))

    if(op == 1):
        rsa.main_rsa()

    elif(op == 0): 
        break