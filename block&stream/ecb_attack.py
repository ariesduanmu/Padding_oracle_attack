import os
import base64
from implement.ecb import encrypt_ecb, decrypt_ecb
from random import randint


class Cookie():
    def __init__(self, secret_plaintext):
        self.key = os.urandom(16)
        self.random_prefix = os.urandom(randint(10,20))
        self.secret_plaintext = secret_plaintext


    def encrypt_with_random_prefix(self, inputtext):
        return encrypt_ecb(self.random_prefix + inputtext + self.secret_plaintext, self.key)

    def encrypt_without_prefix(self, inputtext):
        return encrypt_ecb(inputtext + self.secret_plaintext, self.key)

    def profile_encrypt(self, email):
        return encrypt_ecb(self._profile_for(email), self.key)

    def profile_role(self, ciphertext):
        plaintext = decrypt_ecb(ciphertext, self.key)
        cookie_parsed = self._parse(plaintext)
        return cookie_parsed["role"]

    def _parse(self, string):
        string = string.decode()
        string = string.split('&')
        dic = {}
        for s in string:
            s = s.split('=')
            if s[0] not in dic:
                dic[s[0]] = s[1]
        return dic

    def _profile_for(self, email):
        email = email.replace(b'&',b'').replace(b'=',b'')
        return b'email=' + email + b'&uid=10&role=user'

def ecb_detect(encrypt_fn):
    key = os.urandom(16)
    plaintext = bytearray([1] * 100)
    ciphertext = encrypt_fn(plaintext, key)
    if ciphertext[16:32] == ciphertext[32:48]:
        return True
    return False

def block_size(plaintext, encrypt_fn, key = None):
    i = 1
    
    size = len(encrypt_fn(b'' + plaintext, key)) if key else len(encrypt_fn(b'' + plaintext))

    while True:
        pre = bytes([0] * i)
        bsize = len(encrypt_fn(pre + plaintext, key)) if key else len(encrypt_fn(pre + plaintext))
        if size != bsize:
            return bsize - size
        i += 1


def change_profile_role_attack(cookie):
    email1 = b'foo@bar.coadmin' + bytes([0x0b] * 11)
    email2 = b'foo@bar.commm'

    ciphertext1 = cookie.profile_encrypt(email1)
    ciphertext2 = cookie.profile_encrypt(email2)
    ciphertext = ciphertext2[0:32] + ciphertext1[16:32]
    print(cookie.profile_role(ciphertext))


def unknown_plaintext_attack(cookie):
    
    bsize = block_size(b'', cookie.encrypt_without_prefix)
    known_secret = b''
    finish = False
    while not finish:
        finish = True
        pre = bytes([0] * ((bsize - len(known_secret) % bsize) - 1))
        b = len((pre + known_secret)) // bsize
        c1 = cookie.encrypt_without_prefix(pre)

        for i in range(256):
            c2 = cookie.encrypt_without_prefix(pre + known_secret + bytes([i]))
            if c1[bsize * b:bsize * (b+1)] == c2[bsize * b:bsize * (b+1)]:
                finish = False
                known_secret += bytes([i])
                break
    return known_secret

def unknown_plaintext_with_prefix_attack(cookie):
    c1 = cookie.encrypt_with_random_prefix(b'')
    c2 = cookie.encrypt_with_random_prefix(b'0')
    bsize = block_size(b'', cookie.encrypt_with_random_prefix)

    for i in range(0,len(c1),bsize):
        if c1[i:i+bsize] != c2[i:i+bsize]:
            prefix_block = i // bsize
            break
    
    for i in range(bsize):
        c = cookie.encrypt_with_random_prefix(bytes([0] * (2 * bsize + i)))
        
        if c[(prefix_block + 1) * bsize:(prefix_block + 2) * bsize] ==\
           c[(prefix_block + 2) * bsize:(prefix_block + 3) * bsize]:
            prefix_mod = bsize - i if i > 0 else 0
            break

    known = b''
    finish = False
    
    while not finish:
        finish = True
        pre = bytes([0] * ((bsize - len(known) % bsize) - 1 + (bsize - prefix_mod)))
        b = ((len((pre + known)) - (bsize - prefix_mod)) // bsize ) + prefix_block + 1
        c1 = cookie.encrypt_with_random_prefix(pre)

        for i in range(256):
            c2 = cookie.encrypt_with_random_prefix(pre + known + bytes([i]))
            if c1[bsize * b:bsize * (b+1)] == c2[bsize * b:bsize * (b+1)]:
                finish = False
                known += bytes([i])
                break
    return known



def test():
    secret_plaintext = base64.b64decode("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRv\
                                         d24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvb\
                                         iBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW\
                                         91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")
    cookie = Cookie(secret_plaintext)
    change_profile_role_attack(cookie)

    print(unknown_plaintext_attack(cookie))
    print(unknown_plaintext_with_prefix_attack(cookie))


if __name__ == "__main__":
    test()
    