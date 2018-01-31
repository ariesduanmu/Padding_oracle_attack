cipher = 'alp gwcsepul gtavaf, nlv prgpbpsu mb h jcpbyvdlq, ipltga rv glniypfa we ekl 16xs nsjhlcb. px td o lccjdstslpahzn fptspf xstlxzi te iosj ezv sc xcns ttsoic lzlvrmhaw ez sjqijsa xsp rwhr. tq vxspf sciov, alp wsphvcv pr ess rwxpqlvp nwlvvc dyi dswbhvo ef htqtafvyw hqzfbpg, ezutewwm zcep xzmyr o scio ry tscoos rd woi pyqnmgelvr vpm . qbctnl xsp akbflowllmspwt nlwlpcg, lccjdstslpahzn fptspfo oip qvx dfgysgelipp ec bfvbxlrnj ojocjvpw, ld akfv ekhr zys hskehy my eva dclluxpih yoe mh yiacsoseehk fj l gebxwh sieesn we ekl iynfudktru. xsp yam zd woi qwoc.'
cipher_ = ''.join(c if 'a'<=c<='z' else '' for c in cipher)
englishLetterFreq = {' ':13.70, 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}

def score(string):
    score = 0
    for k in englishLetterFreq:
        score += string.count(k.lower()) * englishLetterFreq[k]
    return score

def index_coincidence(string):
    frequences = []
    n = len(string)
    if n == 0 or n - 1 == 0:
        return 1
    for i in range(26):
        s = chr(ord('a') + i)
        f = string.count(s)
        frequences.append(f * (f - 1))
    return sum(frequences) / (n * (n - 1))

def guess_key_length():
    cipher_n = len(cipher_)
    for i in range(1, 21):
        strings = [index_coincidence(cipher_[j::i]) for j in range(i)]
        print(i, strings)
        print()
    #key length = 10

def get_key(key_len):
    ciphertext = [cipher_[i::key_len] for i in range(key_len)]
    #print(ciphertext)
    key = ''
    for i in range(key_len):
        plaints = []
        for j in range(26):
            cs = ciphertext[i]
            p = ''.join(chr((ord(c) - ord('a') - j) % 26 + ord('a')) for c in cs)
            s = score(p)
            plaints += [[j, p, s]]
        
        key += chr(max(plaints, key = lambda x: x[2])[0] + ord('a'))
    return key

def decrypt(key):
    cur_idx = 0
    plaint = ''
    for c in cipher:
        if 'a' <= c <= 'z':
            plaint += chr((ord(c) - ord(key[cur_idx])) % 26 + ord('a'))
            cur_idx = (cur_idx + 1) % len(key)
        else:
            plaint += c
    return plaint

if __name__ == "__main__":
    key = get_key(10)
    print(key)
    #helloworld
    print(decrypt(key))





