#!/usr/bin/env python
from random import choices, choice
from math import sqrt, ceil
from binascii import hexlify, unhexlify

import unittest

# challenge 39
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

def generate_primes_list(n):
    is_prime = [0 if i % 2 == 0 else 1 for i in range(n+1)]
    for i in range(3, int(sqrt(n)) + 1, 2):
        if is_prime[i]:
            for m in range(i * i, n, 2 * i):
                is_prime[m] = 0
    prime_list = [i for i in range(n+1) if is_prime[i] == 1]
    prime_list.insert(0, 2)
    return prime_list

def rsa(keysize):
    e = 3
    bitcount = (keysize + 1) // 2 + 1
    prime_lists = generate_primes_list(2 ** bitcount - 1)
    prime_lists = [p for p in prime_lists if p >= (2 ** (bitcount - 1))]

    while True:
        p = 7
        while (p - 1) % e == 0:
            p = choice(prime_lists)
        
        q = p
        while q == p or (q - 1) % e == 0:
            q = choice(prime_lists)

        n = p * q
        et = (p - 1) * (q - 1)
        try:
            d = invmod(e, et)
            break
        except:
            continue

    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def encryptnum(message, public_key):
    e, n = public_key
    return pow(message, e, n)

def decryptnum(cipher, private_key):
    d, n = private_key
    return pow(cipher, d, n)

def encryptbytes(message_bytes, public_key):
    return encryptnum(int(hexlify(message_bytes).decode(), 16), public_key)

def decryptbytes(cipher, private_key):
    plain_num = decryptnum(cipher, private_key)
    return num_to_bytes(plain_num)

def num_to_bytes(num):
    return unhexlify(hex(num)[2:].encode())
# challenge 40

def crt(plaintext):
    (public_key0, private_key0) = rsa(20)
    (public_key1, private_key1) = rsa(20)
    (public_key2, private_key2) = rsa(20)

    c0 = encryptbytes(plaintext, public_key0)
    c1 = encryptbytes(plaintext, public_key1)
    c2 = encryptbytes(plaintext, public_key2)

    n0 = public_key0[1]
    n1 = public_key1[1]
    n2 = public_key2[1]

    m_s_0 = n1 * n2
    m_s_1 = n0 * n2
    m_s_2 = n0 * n1

    N_012 = n0 * n1 * n2

    r0 = (c0 * m_s_0 * invmod(m_s_0, n0))
    r1 = (c1 * m_s_1 * invmod(m_s_1, n1))
    r2 = (c2 * m_s_2 * invmod(m_s_2, n2))

    r = (r0 + r1 + r2) % N_012

    return r

def cube_root(r):
    return ceil(r ** (1. / 3))


class ChallengeTest(unittest.TestCase):
    def test_challeng39(self):
        public_key, private_key = rsa(20)
        message = b'hi'
        cipher = encryptbytes(message, public_key)
        plain = decryptbytes(cipher, private_key)

        self.assertEqual(message, plain)

    def test_challenge40(self):
        plaintext = b'hi'
        r = crt(plaintext)
        m = cube_root(r)

        self.assertEqual(plaintext, num_to_bytes(m))


if __name__ == "__main__":
    #unittest.main()
    



