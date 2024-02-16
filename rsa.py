from Crypto.Util.number import inverse
from collections import namedtuple
from decimal import Decimal, localcontext
import random
import math


def gen_prime(n):
    while True:
        p = random.randint(2**(n-1), 2**n - 1)
        if is_prime(p):
            return p


def is_prime(num):
    if num == 2:
        return True
    if num % 2 == 0:
        return False
    i = 0
    while i < 100:
        a = random.randint(1, num - 1)
        if pow(a, num - 1, num) != 1:
            return False
        i += 1
    return True


def bytes_needed(n):
    if n == 0:
        return 1
    return int(math.log(n, 256)) + 1


class RSA:
    def __init__(self, p, q):
        n = 0
        try:
            if is_prime(p) is not True or is_prime(q) is not True:
                raise ValueError
            else:
                self.__p = p
                self.__q = q
                n = self.__p * self.__q
        except ValueError:
            exit('number is not prime')
        self.__euler = (self.__p - 1) * (self.__q - 1)
        while 1:
            e = random.randint(1, self.__euler - 1)
            if math.gcd(self.__euler, e) == 1:
                break
        PublicKey = namedtuple('PublicKey', 'n e')
        self.public_key = PublicKey(n, e)
        self.private_key = inverse(e, self.__euler)

    def find_large_prime_factor(self, n):
        for i in range(100):
            a = gen_prime(100)
            if n % a == 0:
                return True

    def secure_parameters(self):
        print("Generating secure parameters")
        while True:
            p, q = gen_prime(1024), gen_prime(1024)
            n = p * q
            self.__euler = (p - 1)*(q - 1)
            e = random.randint(int(pow(2, 128)), int(pow(2, 256)))
            if math.gcd(self.__euler, e) != 1:
                continue
            self.private_key = inverse(e, self.__euler)
            with localcontext() as ctx:
                ctx.prec = 100
                k = int((round(Decimal(n)) ** round(Decimal(0.25), 2)) / round(Decimal(3)))
                if self.private_key < k:
                    continue

            PublicKey = namedtuple('PublicKey', 'n e')
            self.public_key = PublicKey(n, e)
            break

    def regen_private(self, e):
        PublicKey = namedtuple('PublicKey', 'n e')
        self.public_key = PublicKey(self.public_key.n, e)
        self.private_key = inverse(e, self.__euler)

    def encrypt_rsa(self, content):
        if isinstance(content, bytes):
            content = int.from_bytes(content, "big")
        res = pow(content, self.public_key.e, self.public_key.n)
        return int(res).to_bytes(bytes_needed(int(res)), "big")

    def decrypt_rsa(self, content):
        if isinstance(content, bytes):
            content = int.from_bytes(content, "big")
        res = pow(content, self.private_key, self.public_key.n)
        return int(res).to_bytes(bytes_needed(int(res)), "big")