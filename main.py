import attack
from rsa import RSA


def program_1():
    print("Attack 1 - Common modulus case:")

    p = 47864711409716123555436166028758642696441909887103
    q = 91204629252992155248667688538709116776148592385489

    obj_a = RSA(p, q)
    obj_b = RSA(p, q)

    p, q, da = attack.modulus_attack(obj_b.public_key.n, obj_b.public_key.e, obj_b.private_key, obj_a.public_key.e)

    print("B private key:", obj_b.private_key)
    print("A private key:", obj_a.private_key)
    print("A calculated :", da)

    if da == obj_a.private_key:
        print("Attack 1 successful")
    else:
        print("Attack 1 don`t successful")


def program_2():
    print("Attack 2 - Wiener attack:")

    p = 15733439112036677461
    q = 11928399707412783767
    e = 109410315299163392886979402045049646523

    obj = RSA(p, q)
    obj.regen_private(e)

    d = attack.wiener_attack(obj.public_key.n, obj.public_key.e)

    print("private key:", obj.private_key)
    print("calculated :", d)

    if d == obj.private_key:
        print("Wiener attack successful")
    else:
        print("Wiener attack don`t successful")


def program_3():
    print("Attack 3 - Small order attack:")

    data = 55
    print("Cipher text", data)
    obj = RSA(7, 11)
    c = obj.encrypt_rsa(data)

    print("Encrypted text", c)

    dec = attack.small_order_attack(obj.public_key.n, int.from_bytes(c, "big"), obj.public_key.e)

    print("Decrypted text", dec)

    if dec == data:
        print("Attack 3 successful")
    else:
        print("Attack 3 don`t successful")


if __name__ == '__main__':
    program_1()
    program_2()
    program_3()

    obj = RSA(11, 7)
    obj.secure_parameters()
    print('n = ', obj.public_key.n)
    print('e = ', obj.public_key.e)
    print('d = ', obj.private_key)
