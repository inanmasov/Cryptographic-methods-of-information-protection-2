from Crypto.Util.number import inverse
import random
import math


def two_f_s(n):
    while n % 2 == 0:
        n //= 2
    return n


def find_l(s, n):
    while 1:
        a = random.randint(1, n)
        b = pow(a, s, n)

        i = 0
        while 1:
            b_tmp = pow(b, 2**i, n)
            if b_tmp == 1:
                if pow(b, 2**(i-1), n) == -1:
                    break
                else:
                    return pow(b, 2**(i-1), n)
            i += 1

def modulus_attack(n, eb, db, ea):
    try:
        nn = eb * db - 1
        if nn == 0:
            raise ValueError

        s = two_f_s(nn)
        t = find_l(s, n)
        p = math.gcd(t + 1, n)
        q = math.gcd(t - 1, n)
        euler = (p - 1) * (q - 1)
        da = inverse(ea, euler)
        return p, q, da
    except ValueError:
        exit("Wrong numbers")


def wiener_attack(n, e):
    text = 12315464712432645423
    n1, e1 = n, e
    cf = []
    while n1 > 0:
        q, r = divmod(e1, n1)
        cf.append(q)
        e1, n1 = n1, r

    p_prev, p_curr = 1, 0
    q_prev, q_curr = 0, 1
    for i in range(1, len(cf)):
        a_i = cf[i]
        p_next = a_i * p_curr + p_prev
        q_next = a_i * q_curr + q_prev

        if pow(text, e*q_next, n) == text:
            return q_next

        p_prev, q_prev = p_curr, q_curr
        p_curr, q_curr = p_next, q_next

    return None


def small_order_attack(n, c, e):
    i = 1
    c_i = c
    while True:
        c_i = int(pow(c_i, e, n))
        if c_i == c:
            m = int(pow(c, int(pow(e, i - 1)), n))
            return m
        i += 1
