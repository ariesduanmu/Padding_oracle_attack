from ecb import encrypt_ecb, decrypt_ecb
from utilty import equal_length_bytes_xor
import base64

def paddingPKCS7(bytestr, size):
    i = size - (len(bytestr) % size)
    return bytestr + bytes([i] * i)

def unpaddingPKCS7(text):
    i = text[-1]
    return text[:-i]

def encrypt_cbc(plaintext, key, iv):
    plaintext = paddingPKCS7(plaintext, len(key))
    ciphertext = b""
    pre_plaintext_block = iv
    for i in range(0, len(plaintext), len(key)):
        current_plain = plaintext[i:i+len(key)]
        mid_plain = equal_length_bytes_xor(current_plain, pre_plaintext_block)
        current_ciper = encrypt_ecb(mid_plain, key)
        ciphertext += current_ciper
        pre_plaintext_block = current_ciper

    return ciphertext

def decrypt_cbc(ciphertext, key, iv):
    plaintext = b""
    pre_ciphertext_block = iv
    for i in range(0,len(ciphertext),len(key)):
        current_ciper = ciphertext[i:i+len(key)]
        mid_ciper = decrypt_ecb(current_ciper, key)
        plaintext += equal_length_bytes_xor(mid_ciper, pre_ciphertext_block)
        pre_ciphertext_block = current_ciper
    return unpaddingPKCS7(plaintext)    
    
def test():
    def print_output(num, output):
        print("--------{}---------".format(num))
        print(output)
        print("--------{}---------".format(num))
    
    def test_9():
        text = b"YELLOW SUBMARINE"
        size = 20
        print_output(9, paddingPKCS7(text,size))

    def test_10():
        key = b"YELLOW SUBMARINE"
        iv = bytes([0]*len(key))
        cipertext = base64.b64decode(open('texts/10.txt').read())
        plaintext = decrypt_cbc(cipertext, key, iv)
        re_cipher = encrypt_cbc(plaintext, key, iv)
        print_output(10,plaintext)
        print_output(10, re_cipher == cipertext)


    test_9()
    test_10()

if __name__ == "__main__":
    test()
    