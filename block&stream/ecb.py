import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from utilty import random_key

def paddingPKCS7(bytestr, size):
    i = size - (len(bytestr) % size)
    return bytestr + bytes([i] * i)

def unpaddingPKCS7(text):
    i = text[-1]
    return text[:-i]

def isECBMode(string):
    c = [string[i:i+16] for i in range(0,len(string),16)]
    return len(set(c)) < len(c)

def block_size(plaintext, key, encrypt_fn):
    i = 1
    size = len(encrypt_fn(b'' + plaintext, key))
    while True:
        pre = bytes([0] * i)
        bsize = len(encrypt_fn(pre + plaintext, key))
        if size != bsize:
            return bsize - size
        i += 1


def parse(string):
    string = string.decode()
    string = string.split('&')
    dic = {}
    for s in string:
        s = s.split('=')
        if s[0] not in dic:
            dic[s[0]] = s[1]
    return dic

def profile_for(email):
    email = email.replace(b'&',b'').replace(b'=',b'')
    return b'email=' + email + b'&uid=10&role=user'

def profile_encrypt(email, key):
    return encrypt_ecb(profile_for(email), key)

def profile_role(ciphertext, key):
    plaintext = decrypt_ecb(ciphertext, key)
    print(plaintext)
    cookie_parsed = parse(plaintext)
    return cookie_parsed["role"]


def encrypt_ecb(plaintext,key):
    plaintext = paddingPKCS7(plaintext, len(key))
    encrypt= Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).encryptor()
    return encrypt.update(plaintext)

def decrypt_ecb(cipertext, key):
    decrypt = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend()).decryptor()
    return unpaddingPKCS7(decrypt.update(cipertext))

def ecb_unknown_input_attack(plaintext):
    key = random_key(16)
    bsize = block_size(plaintext, key, profile_encrypt)
    known_secret = b''
    finish = False
    while not finish:
        finish = True
        pre = bytes([0] * ((bsize - len(known_secret) % bsize) - 1))
        b = len((pre + known_secret)) // bsize
        c1 = encrypt_ecb(pre + plaintext, key)

        for i in range(256):
            c2 = encrypt_ecb(pre + known_secret + bytes([i]), key)
            if c1[bsize * b:bsize * (b+1)] == c2[bsize * b:bsize * (b+1)]:
                finish = False
                known_secret += bytes([i])
                break
    return unpaddingPKCS7(known_secret)

def ecb_profile_attack(secret_key):
    bsize = block_size(b"foo@bar.com", secret_key, profile_encrypt)
    email = b"foo@bar.com"
    while len(profile_for(email)) % bsize != 0:
        email += b"m"
    ciphertext = profile_encrypt(email[:bsize-11] + b"admin" + email[bsize-6:-1], secret_key)
    encrypted_admin = ciphertext[bsize-5:bsize]
    ciphertext = ciphertext[:-5] + encrypted_admin
    print(profile_role(ciphertext, secret_key))



def test():
    def print_output(num, output):
        print("--------{}---------".format(num))
        print(output)
        print("--------{}---------".format(num))
    
    def test_7():
        ciper = base64.b64decode(open('texts/7.txt').read())
        k = b"YELLOW SUBMARINE"
        print_output(7, decrypt_ecb(ciper,k).decode())

    def test_8():
        print_output(8, [line[:-1] for line in open('texts/8.txt').readlines() if isECBMode(line)])
    
    def test_12():
        key = random_key(16)
        inputtext = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
        print_output(12,  ecb_unknown_input_attack(base64.b64decode(inputtext)) == base64.b64decode(inputtext))

    def test_13():
        key = random_key(16)
        ecb_profile_attack(key)

    test_7()
    test_8()
    test_12()
    test_13()

if __name__ == "__main__":
    test()
    