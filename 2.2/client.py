from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
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

    session_keys = aes_key + mac_key + nonce
    #session_keys_b64 = b64encode(session_keys).decode('ascii')

    parser = argparse.ArgumentParser(
        description='Recebe os dados de login a partir da linha de comando.')
    parser.add_argument('email', type=str,
                        help="Endereço de email do usuário para login")
    parser.add_argument('senha', type=str, help="Senha do usuário para login")
    parser.add_argument('pubkey_fname', type=str,
                        help="Nome do arquivo da chave pública")

    args = parser.parse_args()

    manager = EncryptionManager(aes_key, nonce)

    plaintexts = [
        args.email.encode('ascii'),
        args.senha.encode('ascii')
    ]

    ciphertexts = []

    for m in plaintexts:
        ciphertexts.append(manager.updateEncryptor(m))
    ciphertexts.append(manager.finalizeEncryptor())

    ciphertext = ciphertexts[0] + b' ' + ciphertexts[1]
    ciphertext_b64 = b64encode(ciphertext).decode('ascii')

    #! Encriptação das chaves AES, MAC e IV utilizando a chave pública do servidor.
    with open("my_key_pub.pem", "rb") as public_key_file_object:
        public_key = serialization.load_pem_public_key(public_key_file_object.read(),
                                                       backend=default_backend())

    encrypted_keys = public_key.encrypt(
        session_keys,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    encrypted_keys_b64 = b64encode(encrypted_keys).decode('ascii')

    #! O hmac é gerado a partir das chaves encriptadas concatenadas com a mensagem cifrada.
    h = hmac.new(mac_key, (encrypted_keys + ciphertext), sha256).digest()
    h_b64 = b64encode(h).decode('ascii')

    r = requests.post('http://127.0.0.1:5000/login',
                      data={'session_keys': encrypted_keys_b64, 'ciphertext': ciphertext_b64, 'hmac': h_b64})

    print("Código de resposta:", r.status_code)
    if r.status_code == 302:
        print("Conteúdo do cookie:", r.cookies['session_id'])

    #! Prints temporários
    print("\n")
    print("Conteúdo dos dados da requisição em base64: ")
    print("session_keys:", encrypted_keys_b64)
    print("ciphertext:", ciphertext_b64)
    print("hmac:", h_b64)


if __name__ == "__main__":
    main()
