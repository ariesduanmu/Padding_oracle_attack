import os
import random
from utilty import random_key
from cbc import encrypt_cbc
from ecb import encrypt_ecb
    

def encrypt_oracle(plaintext):
    pre, tail = random.randint(5,10), random.randint(5,10)
    plaintext = os.urandom(pre) + plaintext + os.urandom(tail)
    key_length = 16
    iv = os.urandom(key_length)
    key = random_key(key_length)
    
    return encrypt_ecb(plaintext, key) if random.randint(0,1) == 0 else encrypt_cbc(plaintext,key,iv)

def detect_encrypy():
    plaintext = bytearray([1] * 100)
    ciphertext = encrypt_oracle(plaintext)
    if ciphertext[16:32] == ciphertext[32:48]:
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":
    print(detect_encrypy())