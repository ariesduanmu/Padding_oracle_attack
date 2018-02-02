from implement.cbc import encrypt_cbc, decrypt_cbc
import os

def encrypt_cookie(userdata, key, iv):
    userdata = userdata.replace(';','').replace('=','')
    userdata = b'comment1=cooking%20MCs;userdata=' + userdata.encode('ascii') + b';comment2=%20like%20a%20pound%20of%20bacon'
    
    return encrypt_cbc(userdata, key, iv)
def detect_target(ciphertext, key, iv):
    plaintext = decrypt_cbc(ciphertext, key, iv)
    plaintexts = plaintext.split(b';')
    for p in plaintexts:
        if p == b'admin=true':
            return True
    return False

def bitflipping_attack():
    key = os.urandom(16)
    iv = os.urandom(16)

    ciphertext = list(encrypt_cookie('XXXXXXXXXXXXXXXX:admin<true:XXXX', key, iv))
    ciphertext[32] ^= 1
    ciphertext[38] ^= 1
    ciphertext[43] ^= 1
    print(detect_target(bytes(ciphertext), key, iv))

if __name__ == "__main__":
    bitflipping_attack()
    

