from Crypto.Util.number import *
from random import randint

flag = b'moectf{???}'
p = getPrime(512)
q = getPrime(512)
n = p * q
phi = (p - 1) * (q - 1)
while 1:
    e = randint(2, n)
    if GCD(e, phi) == 1:
        d = pow(e, -1, phi)
        break

menu = '''1. get ciphertext.
2. submit.
3. quit.'''

while 1:
    print(menu)
    choice = int(input())
    if choice == 1:
        m = bytes.fromhex(input("what message(hex form) do u want to encrtpt?\n"))
        if m == b'MoeCTF 2026':
            print('no cheat!')
            continue
        print(pow(bytes_to_long(m), e, n))
    elif choice == 2:
        enc = int(input("plz sumbit the ciphertext.\n"))
        dec = long_to_bytes(pow(enc, d, n))
        if dec == b'MoeCTF 2026':
            print("Welcome to MoeCTF 2026!")
            print(flag)
            exit()
        else:
            print("incorrect!")
    elif choice == 3:
        print("bye!")
        exit()
    else:
        print("invalid input!")
        continue