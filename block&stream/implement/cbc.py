import base64
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

def equal_length_bytes_xor(bytestr1, bytestr2):
    
    return bytes([bytestr1[i] ^ bytestr2[i] for i in range(len(bytestr1))])

def encrypt_cbc(plaintext, key, iv):
    plaintext = paddingPKCS7(plaintext, len(key))
    ciphertext = b""
    pre_plaintext_block = iv
    for i in range(0, len(plaintext), len(key)):
        current_plain = plaintext[i:i+len(key)]
        mid_plain = equal_length_bytes_xor(current_plain, pre_plaintext_block)
        ecb_encrypt= Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
        current_ciper = ecb_encrypt.update(mid_plain)
        ciphertext += current_ciper
        pre_plaintext_block = current_ciper

    return ciphertext

def decrypt_cbc(ciphertext, key, iv):
    plaintext = b""
    pre_ciphertext_block = iv
    for i in range(0,len(ciphertext),len(key)):
        current_ciper = ciphertext[i:i+len(key)]
        ecb_decrypt = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
        mid_ciper = ecb_decrypt.update(current_ciper)
        plaintext += equal_length_bytes_xor(mid_ciper, pre_ciphertext_block)
        pre_ciphertext_block = current_ciper
    return padding_validation(plaintext)

def test():
    key = b"YELLOW SUBMARINE"
    iv = bytes([0] * 16)
    plaintext = b"this is a test"
    ciphertext = encrypt_cbc(plaintext, key, iv)
    print(decrypt_cbc(ciphertext, key, iv) == plaintext)

if __name__ == "__main__":
    test()