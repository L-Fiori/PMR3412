from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
from hashlib import sha256
import os
import argparse
import requests
import hmac


class EncryptionManager:
    def __init__(self, aes_key, nonce):
        aes_context = Cipher(algorithms.AES(aes_key), modes.CTR(
            nonce), backend=default_backend())
        self.encryptor = aes_context.encryptor()
        self.decryptor = aes_context.decryptor()

    def updateEncryptor(self, plaintext):
        return self.encryptor.update(plaintext)

    def finalizeEncryptor(self):
        return self.encryptor.finalize()

    def updateDecryptor(self, ciphertext):
        return self.decryptor.update(ciphertext)

    def finalizeDecryptor(self):
        return self.decryptor.finalize()


def main():
    aes_key = os.urandom(32)
    mac_key = os.urandom(32)
    nonce = os.urandom(16)

    session_keys_b64 = b64encode(aes_key + mac_key + nonce).decode('ascii')

    parser = argparse.ArgumentParser(
        description='Recebe os dados de login a partir da linha de comando.')
    parser.add_argument('email', type=str,
                        help="Endereço de email do usuário para login")
    parser.add_argument('senha', type=str, help="Senha do usuário para login")

    args = parser.parse_args()

    manager = EncryptionManager(aes_key, nonce)

    plaintexts = [
        args.email.encode('ascii'),
        args.senha.encode('ascii')
    ]

    ciphertexts = []
    ciphertexts_b64 = []

    for m in plaintexts:
        ciphertexts.append(manager.updateEncryptor(m))
    ciphertexts.append(manager.finalizeEncryptor())

    ciphertext = ciphertexts[0] + b' ' + ciphertexts[1]
    ciphertext_b64 = b64encode(ciphertext).decode('ascii')

    #! O hmac será gerado com base na concatenação do email e senha encriptados
    h = hmac.new(mac_key, (ciphertexts[0] +
                           ciphertexts[1]), sha256).digest()
    h_b64 = b64encode(h).decode('ascii')

    r = requests.post('http://127.0.0.1:5000/login',
                      data={'session_keys': session_keys_b64, 'ciphertext': ciphertext_b64, 'hmac': h_b64})

    print("Código de resposta:", r.status_code)
    if r.status_code == 302:
        print("Conteúdo do cookie:", r.cookies['session_id'])

    #! Prints temporários
    print("\n")
    print("Conteúdo dos dados da requisição em base64: ")
    print("session_keys:", session_keys_b64)
    print("ciphertext:", ciphertext_b64)
    print("hmac:", h_b64)


if __name__ == "__main__":
    main()
