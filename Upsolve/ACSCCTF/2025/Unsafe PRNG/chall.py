from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
import random

seed = ## REDACTED ##
flag = b"acsc{## REDACTED ##}"
assert seed.bit_length() == 8192
assert len(flag) == 32
random.seed(seed)

def randfunc(n):
    return random.randbytes(n)

key = RSA.generate(1024, randfunc=randfunc, e=3)

print("n:", hex(key.n)[2:])

for i in range(5):
    cipher = PKCS1_v1_5.new(key, randfunc=randfunc)
    print("1) Test Encrypt")
    print("2) Flag Encrypt")
    print("3) Exit")
    choice = int(input(">>> ").strip())
    if choice == 1:
        message = input("Plaintext to encrypt? >>> ").encode()
        print("Ciphertext:", cipher.encrypt(message).hex())
    elif choice == 2:
        print("Ciphertext:", cipher.encrypt(flag).hex())
    elif choice == 3:
        break
    else:
        print("Wrong choice")

print("Bye!")
