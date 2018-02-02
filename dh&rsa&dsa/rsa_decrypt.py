from random import choices, choice
from math import sqrt, ceil
from binascii import hexlify, unhexlify


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






