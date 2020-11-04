import hashlib
from termcolor import colored

print("----------------> GERADOR E TRADUTOR DE HASHES <------------------------\n\n")

def main():

    modoEscolhido = input(print("Escolha uma das opções do menu:\n1 - Gerador de Hash\n2 - Tradutor de Hash\n\n-> Escolha: "))

    try:
        modoEscolhido = int(modoEscolhido)

        if modoEscolhido == 1:
            geradorHash()

        elif modoEscolhido == 2:
            tradutorHash()

        else:
            print("Esta opção não está disponível, responda com 1 OU 2")
            main()

    except:
        print("Verifique o formato da opção inserida, responda apenas com o número 1 ou 2")
        main()


def validaOpcao(opcaoEscolhida, senhaInformada):

    if opcaoEscolhida == 1:
        resultado = hashMD5(senhaInformada)

    elif opcaoEscolhida == 2:
        resultado = hashSHA1(senhaInformada)

    elif opcaoEscolhida == 3:
        resultado = hashSHA224(senhaInformada)

    elif opcaoEscolhida == 4:
        resultado = hashSHA256(senhaInformada)

    elif opcaoEscolhida == 5:
        resultado = hashSHA384(senhaInformada)

    elif opcaoEscolhida == 6:
        resultado = hashSHA512(senhaInformada)

    return resultado


def geradorHash():
    escolha = input(("\n1 - MD5\n2 - SHA1\n3 - SHA224\n4 - SHA256\n5 - SHA384\n6 - SHA512\n\n-> Escolha o Algoritmo a ser utilizado: "))

    try:
        escolha = int(escolha)

        if escolha > 0 and escolha <= 6:
            senhaInformada = input("-> Digite a senha que será transformada em hash: ").encode('utf-8')

            if validaOpcao(escolha, senhaInformada):
                resposta = validaOpcao(escolha, senhaInformada)
                print("--> Hash gerada: {}".format(colored(resposta, 'green')))

        else:
            print(colored("\nEscolha uma opção válida, as opções vão do 1 ao 6!\n", "red"))
            geradorHash()

    except:
        print(colored("\nSomente NÚMEROS entre 1 e 6 são aceitos como opções!\n", "red"))
        geradorHash()


def tradutorHash():
    escolha = input("\nFormato da Hash:\n1 - MD5\n2 - SHA1\n3 - SHA224\n4 - SHA256\n5 - SHA384\n6 - SHA512\n\n-> Opção: ")

    try:
        escolha = int(escolha)

        if escolha > 0 and escolha <= 6:

            hashInformada = input("\nInsira uma hash: ").strip()
            wordlist = input("Informe uma wordlist: ")
            wordlist_read = open(wordlist, "r")
            print("\n")

            for senhas in wordlist_read:
                senhas_strip = senhas.strip()

                buscaSenha = validaOpcao(escolha, senhas_strip.encode('utf-8'))

                print("-Testando Possível Senha: {}".format(colored(senhas, 'red')))

                if hashInformada == buscaSenha:

                    print("--> Hash traduzida: {}".format(colored(senhas, 'green')))
                    break

        else:
            print(colored("\n-> Escolha uma opção válida, as opções vão do 1 até o 6!\n", 'red'))
            tradutorHash()

    except:
        print(colored("\n-> Verifique a opção inserida, letras não são aceitas como opções, responda apenas com números entre 1 e 6!\n", "red"))
        tradutorHash()



def hashMD5(senhaInformada):
    md5 = hashlib.md5(senhaInformada)
    return md5.hexdigest()

def hashSHA1(senhaInformada):
    sha1Hash = hashlib.sha1(senhaInformada)
    return sha1Hash.hexdigest()

def hashSHA224(senhaInformada):
    sha224 = hashlib.sha224(senhaInformada)
    return sha224.hexdigest()

def hashSHA256(senhaInformada):
    sha256 = hashlib.sha256(senhaInformada)
    return sha256.hexdigest()

def hashSHA384(senhaInformada):
    sha384 = hashlib.sha384(senhaInformada)
    return sha384.hexdigest()

def hashSHA512(senhaInformada):
    sha512 = hashlib.sha512(senhaInformada)
    return sha512.hexdigest()


main()


