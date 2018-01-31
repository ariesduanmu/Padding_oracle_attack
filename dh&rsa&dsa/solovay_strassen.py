import random
#prime algorithm
def solovay_strassen(n):
    a = random.randint(1, n-1)
    #legendre
    # x = (a / n)
    if x == 0:
        return "n is composite"
    y = pow(a, (n - 1) / 2, n)
    if x % n == y % n:
        return "n is prime"
    return "n is composite"

def miller_rabin(n):
    a = random.randint(1, n-1)
    # n-1 = (2 ^ k) * m
    b = pow(a, m, n)
    if b % n:
        return "n is prime"
    for i in range(k):
        if b % n == n - 1:
            return "n is prime"
        else:
            b = (b * b) % n
    return "n is composite"

def legendre(a, p):
    if a % p == 0 or p % a == 0:
        return 0

    k = 1
    while True:
        if a < p:
            if a % 4 == 3 and p % 4 == 3:
                k *= -1
            tmp = a
            a = p
            p = a
        a = a % p
        if a == 2:
            return 1 if (n % 8) ** 2 == 1 else -1
        # a = (2 ^ k) * t => (a / n) = ((2 / n) ^ k) * (t / n)



