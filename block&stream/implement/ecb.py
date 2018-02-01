from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def paddingPKCS7(bytestr, size):
    i = size - (len(bytestr) % size)
    return bytestr + bytes([i] * i)

def padding_validation(text):
    i = text[-1]
    if bytes([i] * i) != text[-i:]:
        raise ValueError('{} bad padding'.format(text))
    return text[:-i]

def encrypt_ecb(plaintext,key):
    plaintext = paddingPKCS7(plaintext, len(key))
    encrypt= Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
    return encrypt.update(plaintext)

def decrypt_ecb(cipertext, key):
    decrypt = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
    return padding_validation(decrypt.update(cipertext))

def test():
    key = b"YELLOW SUBMARINE"
    plaintext = b"this is a test"
    ciphertext = encrypt_ecb(plaintext, key)
    print(decrypt_ecb(ciphertext, key) == plaintext)

if __name__ == "__main__":
    test()