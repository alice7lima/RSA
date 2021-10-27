import rsa

while(1):

    print("1 - Iniciar a programa", end='\n')
    print("0 - Encerrar o programa", end='\n')
    op = int(input("Escolha uma opcao: "))

    if(op == 1):
        print("Digite a mensagem que deseja cifrar (sem acento):")
        rsa.main_rsa()

    if(op == 0): 
        break