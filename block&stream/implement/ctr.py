from ecb import encrypt_ecb
from base64 import b64decode
import struct

def equal_length_bytes_xor(bytestr1, bytestr2):
    return bytes([bytestr1[i] ^ bytestr2[i] for i in range(len(bytestr1))])

def encrypt_ctr(plaintext, key, nonce = 0):
    counter = 0
    ciphertext = b""
    while counter * 16 <= len(plaintext):
        nc = struct.pack('<QQ', nonce, counter)
        ctext = encrypt_ecb(nc, key, False)
        if len(plaintext) >= (counter + 1) * 16:
            ciphertext += equal_length_bytes_xor(plaintext[counter * 16:(counter+1) * 16], ctext)
        else:
            ciphertext += equal_length_bytes_xor(plaintext[counter * 16:],ctext)
        counter += 1
    return ciphertext

def decrypt_ctr(ciphertext, key, nonce = 0):
    return encrypt_ctr(ciphertext, key, nonce)

def test():
    string = b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='
    key = b'YELLOW SUBMARINE'
    ciphertext = decrypt_ctr(b64decode(string), key)
    print(encrypt_ctr(ciphertext,key) == b64decode(string))

if __name__ == "__main__":
    test()