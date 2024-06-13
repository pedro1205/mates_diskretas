import secrets as sc
from tinyec import registry

curva = registry.get_curve('secp192r1')

clavePriv = sc.randbelow(curva.field.n)
clavePub = clavePriv * curva.g
comClavePub = '0' + str(2 + clavePub.y % 2) + str(hex(clavePub.x)[2:])
print("Clave privada: ", hex(clavePriv)[2:])
print("Clave publica: ", comClavePub)

def xor_simple(data, clave):
    return bytes(a ^ b for a, b in zip(data, clave))

def enkryptar(msg, pubClave):
    cifradoClavePriv = sc.randbelow(curva.field.n)
    claveKompartida = cifradoClavePriv * pubClave
    claveKompartidaB = claveKompartida.x.to_bytes((claveKompartida.x.bit_length() + 7) // 8, 'big')
    ciphertxt = xor_simple(msg, claveKompartidaB)
    return ciphertxt, cifradoClavePriv * curva.g

def desenkryptar(cMsg, privClave):
    (cTxt, ciphertxtClavePub) = cMsg
    claveKompartida = privClave * ciphertxtClavePub
    claveKompartidaB = claveKompartida.x.to_bytes((claveKompartida.x.bit_length() + 7) // 8, 'big')
    plaintext = xor_simple(cTxt, claveKompartidaB)
    return plaintext

mensaje = b"Hola, me gustas"
eMsg = enkryptar(mensaje, clavePub)
print("\nMensaje encriptado:", eMsg[0])

deMsg = desenkryptar(eMsg, clavePriv)
print("Mensaje desencriptado:", deMsg.decode('utf-8'))

def main():
    while True:
        plaintext = input("\nIngrese el texto a encriptar (presione Enter para salir): ")
        if not plaintext:
            break

        eMsg = enkryptar(plaintext.encode('utf-8'), clavePub)
        print("Mensaje encriptado: ", eMsg[0])
        deMsg = desenkryptar(eMsg, clavePriv)
        print("Mensaje desencriptado: ", deMsg.decode('utf-8'))


if __name__ == "__main__":
    main()
