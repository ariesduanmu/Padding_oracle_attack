import os
from base64 import b64decode, b64encode
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class Cookie():
    def __init__(self):
        self._key = os.urandom(16)
        
    def get_ciphertext(self, message):
        iv = os.urandom(16)
        return b64encode(self.generate_ciphertext(iv, message)).decode()

    def generate_ciphertext(self, iv, message):
        message = self._paddingPKCS7(message.encode(), 16)
        return iv + self._encrypt_cbc(message, self._key, iv)

    
    def get_plaintext(self, ciphertext):
        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:16]
        ciphertext = ciphertext[16:]
        plaintext = self._decrypt_cbc(ciphertext, self._key, iv)
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