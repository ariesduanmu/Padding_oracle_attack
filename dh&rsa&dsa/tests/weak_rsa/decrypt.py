from random import choices, choice
from math import sqrt, ceil
from binascii import hexlify, unhexlify
from wiener_attack import WienerAttack

def extended_gcd(aa, bb):
    lastremainder, remainder = abs(aa), abs(bb)
    x, lastx, y, lasty = 0, 1, 1, 0
    while remainder:
        lastremainder, (quotient, remainder) = remainder, divmod(lastremainder, remainder)
        x, lastx = lastx - quotient*x, x
        y, lasty = lasty - quotient*y, y
    return lastremainder, lastx * (-1 if aa < 0 else 1), lasty * (-1 if bb < 0 else 1)

def invmod(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError
    return x % m

def private(n, e, p, q):
    et = (p - 1) * (q - 1)
    d = invmod(e, et)
    return (d, n)


def decryptnum(cipher, private_key):
    d, n = private_key
    return pow(cipher, d, n)

def decryptbytes(cipher, private_key):
    plain_num = decryptnum(cipher, private_key)
    return num_to_bytes(plain_num)

def num_to_bytes(num):
    return unhexlify(b'0' + hex(num)[2:].encode())


if __name__ == "__main__":
    n = 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676298471525243254143375622365552296949413920679290535717172319562064308937342567483690486592868352763021360051776130919666984258847567032959931761686072492923
    e = 68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605
    c = 293792738930806473043362408865328816287441045624879757658311913421709629830459147001874022619053834436656776844217383046081493640274421712968040869174651239233039876991334823008822132067871053934110275331573032589519744166170666015147429094399160461619773963895662688636761506290931246128202368412403823287790

    wiener_attack = WienerAttack(n, e)
    p = int(wiener_attack.p)
    q = int(wiener_attack.q)

    private_key = private(n, e, p, q)
    print(decryptbytes(c, private_key))




