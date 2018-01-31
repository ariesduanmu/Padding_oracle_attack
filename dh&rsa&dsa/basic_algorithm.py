
def extended_gcd(a, b):
    t0, t, s0, s = 0, 1, 1, 0
    while b != 0:
        q, r = divmod(a, b)

        temp = t0 - q * t
        t0 = t
        t = temp

        temp = s0 - q * s
        s0 = s
        s = temp

        a = b
        b = r
    return a, s, t



def square_and_multiply(x, c, n):
    z = 1
    c = bin(c)[2:]
    for i in range(len(c)):
        z = (z * z) % n
        if c[i] == "1":
            z = (z * x) % n
    return z

print(square_and_multiply(10, 4, 19))