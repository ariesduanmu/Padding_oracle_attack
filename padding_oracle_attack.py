#!/usr/bin/env python

import os
from base64 import b64decode, b64encode
from binascii import hexlify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class Cookie():
    def __init__(self):
        self._key = os.urandom(16)
        
    def get_cookie(self, message):
        iv = os.urandom(16)
        return b64encode(self.generate_cookie(iv, message)).decode()

    def generate_cookie(self, iv, message):
        message = self._paddingPKCS7(message.encode(), 16)
        return iv + self._encrypt_cbc(message, self._key, iv)

    
    def get_message(self, cookie):
        cookie = b64decode(cookie)
        iv = cookie[:16]
        cipertext = cookie[16:]
        plaintext = self._decrypt_cbc(cipertext, self._key, iv)
        plaintext = self._unpaddingPKCS7(plaintext)
        return plaintext


    def _unpaddingPKCS7(self, text):
        i = text[-1]
        
        if bytes([i] * i) != text[-i:]:
            raise ValueError('{} bad padding'.format(text))
        return text[:-i]

    def _paddingPKCS7(self, bytestr, size):
        i = size - (len(bytestr) % size)
        return bytestr + bytes([i] * i)

    def _encrypt_cbc(self, inputtext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(inputtext)

    def _decrypt_cbc(self, cipertext, key, iv):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        return cipher.decryptor().update(cipertext)

def decrypt_last_block(mycookie, pre_block, last_second_block, last_block):

    known_bytes = b''
    while len(known_bytes) < 16:
        n = len(known_bytes)
        for i in range(256):
            if i != n + 1:
                b1 = bytes([0] * (15 - n) + [i]) + known_bytes
                b2 = bytes([0] * (15 - n) + [n + 1] * (n + 1))
                
                current_last_second_block = bytes([last_second_block[i] ^ b1[i] ^ b2[i] for i in range(16)])
                cookie = pre_block + current_last_second_block + last_block
                try:
                    mycookie.get_message(b64encode(cookie).decode())
                    known_bytes = bytes([i]) + known_bytes
                    break
                except:
                    continue
        else:
            known_bytes = bytes([n+1]) + known_bytes
    return known_bytes

def decrypt_attack(mycookie, cookie):
    cookie = b64decode(cookie)
    
    blocks = [cookie[i:i+16] for i in range(0,len(cookie),16)]
    plaintext = b""
    for i in range(1, len(blocks)):
        last_block = blocks[i]
        last_second_block = blocks[i-1]
        pre_block = b''.join(blocks[:i-1])

        plaintext += decrypt_last_block(mycookie, pre_block, last_second_block, last_block)
    return plaintext

def encrypt_attact(mycookie, cookie, plaintext):
    cookie = b64decode(cookie)

    #padding plaintext
    p = 16 - (len(plaintext) % 16)
    plaintext = plaintext.encode() + bytes([p] * p)

    if len(cookie) >= len(plaintext) + 16:
        cookie = cookie[:len(plaintext) + 16]
    else:
        k = len(plaintext) + 16 - len(cookie)
        cookie += bytes([65] * k)

    cookie_plain = decrypt_attack(mycookie, b64encode(cookie))[-16:]
    plaintext_blocks = [plaintext[i:i+16] for i in range(0, len(plaintext), 16)]

    ciphertext = cookie[-16:]

    for i in range(len(plaintext_blocks) - 1, -1, -1):
        plain = plaintext_blocks[i]
        last_second_cookie = cookie[-32:-16]
        cipher = bytes([last_second_cookie[j] ^ cookie_plain[j] ^ plain[j] for j in range(16)])  

        cookie = cookie[:-32] + cipher
        cookie_plain = decrypt_attack(mycookie, b64encode(cookie))[-16:]

        ciphertext = cipher + ciphertext
        
    return b64encode(ciphertext).decode()

if __name__ == "__main__":
    message = "The MAC bug allows an attacker to submit arbitrary ciphertexts and IV's which are processed by the server in CBC mode"
    mycookie = Cookie()
    cookie= mycookie.get_cookie(message)
    plain = "IV's which are processed by the server in CBC mode"
    cipher = encrypt_attact(mycookie, cookie, plain)
    print(cipher)
    print(mycookie.get_message(cipher))

    