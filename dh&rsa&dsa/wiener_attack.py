import sys
from sympy.solvers import solve
from sympy import Symbol
from rsa_decrypt import private, decryptbytes
# A reimplementation of pablocelayes rsa-wiener-attack for this purpose
# https://github.com/pablocelayes/rsa-wiener-attack/

class WienerAttack(object):
    def rational_to_contfrac (self, x, y):
        a = x//y
        if a * y == x:
            return [a]
        else:
            pquotients = self.rational_to_contfrac(y, x - a * y)
            pquotients.insert(0, a)
            return pquotients

    def convergents_from_contfrac(self, frac):    
        convs = [];
        for i in range(len(frac)):
            convs.append(self.contfrac_to_rational(frac[0:i]))
        return convs

    def contfrac_to_rational (self, frac):
        if len(frac) == 0:
            return (0,1)
        elif len(frac) == 1:
            return (frac[0], 1)
        else:
            remainder = frac[1:len(frac)]
            (num, denom) = self.contfrac_to_rational(remainder)
            return (frac[0] * num + denom, num)

    def is_perfect_square(self, n):
        h = n & 0xF; 
        if h > 9:
            return -1 

        if ( h != 2 and h != 3 and h != 5 and h != 6 and h != 7 and h != 8 ):
            t = self.isqrt(n)
            if t*t == n:
                return t
            else:
                return -1
        
        return -1

    def isqrt(self, n):
        if n == 0:
            return 0
        a, b = divmod(n.bit_length(), 2)
        x = 2**(a+b)
        while True:
            y = (x + n//x)//2
            if y >= x:
                return x
            x = y


    def __init__(self, n, e):
        self.d = None
        self.p = None
        self.q = None
        sys.setrecursionlimit(100000)
        frac = self.rational_to_contfrac(e, n)
        convergents = self.convergents_from_contfrac(frac)
        
        for (k,d) in convergents:
            if k!=0 and (e*d-1)%k == 0:
                phi = (e*d-1)//k
                s = n - phi + 1
                discr = s*s - 4*n
                print(s, discr)
                if(discr>=0):
                    t = self.is_perfect_square(discr)
                    if t!=-1 and (s+t)%2==0:
                        self.d = d
                        x = Symbol('x')
                        roots = solve(x**2 - s*x + n, x)
                        if len(roots) == 2:
                            self.p = roots[0]
                            self.q = roots[1]
                        break

def test():
    n = 573177824579630911668469272712547865443556654086190104722795509756891670023259031275433509121481030331598569379383505928315495462888788593695945321417676298471525243254143375622365552296949413920679290535717172319562064308937342567483690486592868352763021360051776130919666984258847567032959931761686072492923
    e = 68180928631284147212820507192605734632035524131139938618069575375591806315288775310503696874509130847529572462608728019290710149661300246138036579342079580434777344111245495187927881132138357958744974243365962204835089753987667395511682829391276714359582055290140617797814443530797154040685978229936907206605
    c = 293792738930806473043362408865328816287441045624879757658311913421709629830459147001874022619053834436656776844217383046081493640274421712968040869174651239233039876991334823008822132067871053934110275331573032589519744166170666015147429094399160461619773963895662688636761506290931246128202368412403823287790

    wiener_attack = WienerAttack(n, e)
    p = int(wiener_attack.p)
    q = int(wiener_attack.q)

    print(p)
    print(q)
    #private_key = private(n, e, p, q)
    #print(private_key)
    #print(decryptbytes(c, private_key))

if __name__ == "__main__":
    test()

