import ast

p = int(input("p = "))
g = int (input("g = "))
alice_public = int(input("alice_public = "))
bob_public = int (input("bob_public = "))
alice_private  = int(input())
ciphertext  =ast.literal_eval(input("ciphertext = "))


# alice_public = pow(g,alice_private, p) #生成Alice的公钥
# bob_public = pow(g,bob_private, p)     #生成Bob的公钥
shared_secret = pow(bob_public,alice_private, p)#共享密钥
key = shared_secret % 256
# flag = b"moectf{...}"
# ciphertext = [x ^ key for x in flag]#逐字节异或加密

text = bytes(x^key for x in ciphertext)
print(text.decode())

# print(f"p = {p}")
# print(f"g = {g}")
# print(f"alice_public = {alice_public}")
# print(f"bob_public = {bob_public}")
# print(f"alice_private = {alice_private}") #泄露了私钥!
# print(f"ciphertext = {ciphertext}")
"""
p = 170141183460469231731687303715884105727
g = 3
alice_public = 42348823944539164637318232035973172471
bob_public = 101533001028006636636416596392258549313
alice_private = 20260704
ciphertext = [45, 47, 37, 35, 52, 38, 59, 36, 40, 31, 48, 50, 41, 54, 33, 52,37, 31, 43, 37, 57, 31, 51, 40, 47, 53, 44, 36, 31, 51, 52, 33, 57, 31, 51,37, 35, 50, 37, 52, 61]
"""

