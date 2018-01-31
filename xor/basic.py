import unittest
from base64 import b64encode, b64decode
from binascii import hexlify, unhexlify
from utilty import *


def encode_(string, key):
    return hexlify(bytestr_xor_shortKey(string,key))

def detectCharacterXOR(filename):
    file = open(filename, 'rb')
    ss = [findKey(string.strip(b'\n').decode()) for string in file.readlines()]
    file.close()
    return max(ss, key = lambda x: score(x))

def findKey(string):
    string = bytes.fromhex(string)
    possible_results = [''.join([chr(s ^ num) for s in string]) for num in range(256)]
    return max(possible_results, key = lambda x: score(x))

def fixedXOR(string1, string2):
    bytes1 = unhexlify(string1)
    bytes2 = unhexlify(string2)
    return hexlify(bytes(bytes1[i] ^ bytes2[i] for i in range(len(bytes1))))

def hex2base64(string):
    return b64encode(bytes.fromhex(string))

def keysize(ciper):
    nomal = [(i,float(hamming_distance(ciper[:i],ciper[i:i*2]) +
                   hamming_distance(ciper[i:i*2],ciper[i*2:i*3]) + 
                   hamming_distance(ciper[i*2:i*3],ciper[i*3:i*4])) / float(i * 3)) 
             for i in range(2,41)]
    
    return list(map(lambda x:x[0], sorted(nomal, key = lambda x: x[1])[:3]))

def decode(filename):
    ciper = b64decode(open(filename,'rb').read())
    ksize = max(keysize(ciper))
    
    cs = [ciper[i:i+ksize] for i in range(0, len(ciper), ksize)]
    blocks = [[c[i] for c in cs if i < len(c)] for i in range(ksize)]
    keys = [max([(i, bytestr_xor_singleKey(block, i)) for i in range(256)], key=lambda x:score(x[1]))[0] for block in blocks]
    
    return bytestr_xor_shortKey(ciper, keys).decode('ascii')

def hamming_distance(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    r = 0
    for i in range(len(b1)):
        r += bin(b1[i] ^ b2[i]).count('1')
    return r

class cryptopalsTest(unittest.TestCase):
    def test_1(self):
        string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
        target = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

        self.assertEqual(hex2base64(string), target)

    def test_2(self):
        string1 = '1c0111001f010100061a024b53535009181c'
        string2 = '686974207468652062756c6c277320657965'
        target = b'746865206b696420646f6e277420706c6179'

        self.assertEqual(fixedXOR(string1, string2), target)

    def test_3(self):
        string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
        self.assertEqual(findKey(string), "Cooking MC's like a pound of bacon")

    def test_4(self):
        self.assertEqual(detectCharacterXOR('texts/4.txt'),'Now that the party is jumping\n')

    def test_5(self):
        key = b"ICE"
        string = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        target = b"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

        self.assertEqual(encode_(string, key), target)

    def test_6(self):
        hamming_string1 = b"this is a test"
        hamming_string2 = b"wokka wokka!!!"

        self.assertEqual(hamming_distance(hamming_string1, hamming_string2), 37)
        
def test():
    print("test6:")
    print(decode('texts/6.txt'))
    
if __name__ == "__main__":
    
    test()
    unittest.main()


