from base64 import b64decode
from basic import score


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

def guess_key_length(ciphertext, max_len = 20):
    for i in range(1, max_len + 1):
        strings = [index_coincidence(ciphertext[j::i]) for j in range(i)]
        print(i, strings)
        print()
    

def get_key(ciphertext, key_len):
    ciphertext_blocks = [ciphertext[i::key_len] for i in range(key_len)]
    key = ''
    for i in range(key_len):
        plaints = []
        cipher = ciphertext_blocks[i]
        for j in range(26):
            s = score(''.join(chr((ord(c) - ord('a') - j) % 26 + ord('a')) for c in cipher))
            plaints += [[j, s]]
        key += chr(max(plaints, key = lambda x: x[1])[0] + ord('a'))
    return key

def vigenere(ciphertext, with_punctuation = False):
    ciphertext_without_punctuation = ciphertext
    if with_punctuation:
        ciphertext_without_punctuation = ''.join(c if 'a'<=c<='z' else '' for c in ciphertext)

    guess_key_length(ciphertext_without_punctuation)
    key_len = input("key length:")
    key = get_key(ciphertext_without_punctuation, int(key_len))
    print("[+] Key: " + key)

    cur_idx = 0
    plain = ''
    for c in ciphertext:
        if 'a' <= c <= 'z':
            plain += chr((ord(c) - ord(key[cur_idx])) % 26 + ord('a'))
            cur_idx = (cur_idx + 1) % len(key)
        else:
            plain += c
    print("[+] Plain text: " + plain)




def test():
    cipher = 'alp gwcsepul gtavaf, nlv prgpbpsu mb h jcpbyvdlq, ipltga rv glniypfa we ekl 16xs nsjhlcb. px td o lccjdstslpahzn fptspf xstlxzi te iosj ezv sc xcns ttsoic lzlvrmhaw ez sjqijsa xsp rwhr. tq vxspf sciov, alp wsphvcv pr ess rwxpqlvp nwlvvc dyi dswbhvo ef htqtafvyw hqzfbpg, ezutewwm zcep xzmyr o scio ry tscoos rd woi pyqnmgelvr vpm . qbctnl xsp akbflowllmspwt nlwlpcg, lccjdstslpahzn fptspfo oip qvx dfgysgelipp ec bfvbxlrnj ojocjvpw, ld akfv ekhr zys hskehy my eva dclluxpih yoe mh yiacsoseehk fj l gebxwh sieesn we ekl iynfudktru. xsp yam zd woi qwoc.'
    vigenere(cipher, True)
    
if __name__ == "__main__":
    test()
    