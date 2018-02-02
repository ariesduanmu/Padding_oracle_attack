from base64 import b64decode

englishLetterFreq = {' ':13.70, 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}

def bytestr_xor_singleKey(bytestr, key):
    return ''.join([chr(s ^ key) for s in bytestr])

def bytestr_xor_shortKey(bytestr, key):
    return bytes([bytestr[i] ^ key[i % len(key)] for i in range(len(bytestr))])

def score(string):
    score = 0
    for k in englishLetterFreq:
        score += string.count(k.lower()) * englishLetterFreq[k]
    return score

def detect_single_character_xor(filename):
    file = open(filename, 'rb')
    ss = [decrypt_xord_single_character(string.strip(b'\n').decode()) for string in file.readlines()]
    file.close()
    return max(ss, key = lambda x: score(x))

def decrypt_xord_single_character(string):
    string = bytes.fromhex(string)
    possible_results = [''.join([chr(s ^ num) for s in string]) for num in range(256)]
    return max(possible_results, key = lambda x: score(x))

def keysize(ciper):
    nomal = [(i,float(hamming_distance(ciper[:i],ciper[i:i*2]) +
                   hamming_distance(ciper[i:i*2],ciper[i*2:i*3]) + 
                   hamming_distance(ciper[i*2:i*3],ciper[i*3:i*4])) / float(i * 3)) 
             for i in range(2,41)]
    
    return list(map(lambda x:x[0], sorted(nomal, key = lambda x: x[1])[:3]))

def hamming_distance(b1, b2):
    b1 = bytearray(b1)
    b2 = bytearray(b2)
    
    return sum(bin(b1[i] ^ b2[i]).count('1') for i in range(len(b1)))

def repeating_key_xor(filename):
    ciper = b64decode(open(filename,'rb').read())
    ksize = max(keysize(ciper))
    
    cs = [ciper[i:i+ksize] for i in range(0, len(ciper), ksize)]
    blocks = [[c[i] for c in cs if i < len(c)] for i in range(ksize)]
    keys = [max([(i, bytestr_xor_singleKey(block, i)) for i in range(256)], key=lambda x:score(x[1]))[0] for block in blocks]
    
    return bytestr_xor_shortKey(ciper, keys).decode('ascii')
if __name__ == "__main__":
    pass

