from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from base64 import b64encode, b64decode
from hashlib import sha256
import os
import argparse
import requests
import hmac

ca_root_cert_pem = b'''-----BEGIN CERTIFICATE-----
MIIDqTCCApECFD+Ve9BQTl0k1yEeHYwKPk8V1jfMMA0GCSqGSIb3DQEBCwUAMIGQ
MQswCQYDVQQGEwJCUjESMBAGA1UECAwJU0FPIFBBVUxPMRIwEAYDVQQHDAlTQU8g
UEFVTE8xDjAMBgNVBAoMBUVQVVNQMQwwCgYDVQQLDANQTVIxFTATBgNVBAMMDFBN
UjM0MTIgUm9vdDEkMCIGCSqGSIb3DQEJARYVYW5kcmUua3ViYWdhd2FAdXNwLmJy
MB4XDTIxMTEwODEyMjAyNloXDTIyMTEwODEyMjAyNlowgZAxCzAJBgNVBAYTAkJS
MRIwEAYDVQQIDAlTQU8gUEFVTE8xEjAQBgNVBAcMCVNBTyBQQVVMTzEOMAwGA1UE
CgwFRVBVU1AxDDAKBgNVBAsMA1BNUjEVMBMGA1UEAwwMUE1SMzQxMiBSb290MSQw
IgYJKoZIhvcNAQkBFhVhbmRyZS5rdWJhZ2F3YUB1c3AuYnIwggEiMA0GCSqGSIb3
DQEBAQUAA4IBDwAwggEKAoIBAQDpddQ9pvfFjb2zY3337/0GvYkFuk+VibiBrS3D
1zKTI2G8gQN+SUdxNsO3Mb4npG43em9DmTBO+aHUZ3jRAWqufiXXR/hnwgo5WtPN
RATYmwd3z+GH3MMSe0j1Tw+JmtK7BQKc691yIE6sq47Sy/h+1Pr/8mwQNYSqOxQz
7ZZUKPnLNDxzpYaLTF6ZMb1D7kY+8kS9D6X1vLz/oeVP/y0NEHTQzMTpnfzjj/+B
w+cQeR53Yh6LTZ8RjMC6qzZSpJqcInZiedyhcbQWkoM5otRh6akWkXgCsdLTIaXn
8cHfJw/giCtygu39Ikar7JvN9vgm/1V9VC/MYR/UlHezcsYjAgMBAAEwDQYJKoZI
hvcNAQELBQADggEBACkXSQDUecOuXCXvQLdaOrcgbbQe7Pec6NQYN9wT1m6Jt5DQ
C4qZ80PBx30G7AEGP8yTEV4i7yBXt+xhLhhtYU5lztB/wwf520t2eTgTE8HMZoTx
Pn5KAC7FrBxqL8z2upTXZcm+LkndoF5jVzh5AMu19f1fMkuSKktAIrJyiL2FMqud
bmb2mxSLbEaDV19hn+oOREyhkJ0A/7Hksg3CbY2+NtdyQaGQwoJjil3mOiprzKWx
vgVqM5NlNKvE+U/al87k+ZRQXCVSexEEboVHPRJiFpz8nzfo6OXgwjY5FxmFc4uL
Bo9Bhpaz+8Oo3MmmexmkwUEp6HsdqDlnd8P1o8I=
-----END CERTIFICATE-----
'''


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
    # session_keys_b64 = b64encode(session_keys).decode('ascii')

    parser = argparse.ArgumentParser(
        description='Recebe os dados de login a partir da linha de comando.')
    parser.add_argument('email', type=str,
                        help="Endereço de email do usuário para login")
    parser.add_argument('senha', type=str, help="Senha do usuário para login")
    # parser.add_argument('pubkey_fname', type=str,
    #                    help = "Nome do arquivo da chave pública")

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

    #! Request para obtenção do certificado e posterior carregamento.
    r_crt = requests.get('http://127.0.0.1:5000/crt')
    crt = r_crt.content

    #!Print temporário
    print("Conteúdo da resposta do servidor: ", crt)

    ca_server_cert = x509.load_pem_x509_certificate(crt, default_backend())
    ca_root_cert = x509.load_pem_x509_certificate(
        ca_root_cert_pem, default_backend())

    #! Checa se o CN do requerente é o meu número USP.
    if ca_server_cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value != "10770408":
        raise Exception('CN do requerente não é 10770408.')

    #! Checa se o CN do emissor é igual ao CN do requerente do certificado raiz.
    if ca_root_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value != ca_server_cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value:
        raise Exception(
            'CN do emissor não é igual ao CN do requerente do certificado raiz.')

    #! Checa se a assinatura do certificado do servidor é válida.
    if ca_root_cert.public_key().verify(
            ca_server_cert.signature,
            ca_server_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            ca_server_cert.signature_hash_algorithm):
        raise Exception('Assinatura do certificado inválida.')

    #! Encriptação das chaves AES, MAC e IV utilizando a chave pública do certificado.

    public_key = ca_server_cert.public_key()

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
    # print("\n")
    #print("Conteúdo dos dados da requisição em base64: ")
    #print("session_keys:", encrypted_keys_b64)
    #print("ciphertext:", ciphertext_b64)
    #print("hmac:", h_b64)


if __name__ == "__main__":
    main()
