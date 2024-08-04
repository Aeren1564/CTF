from secret import generate_next_key, flag
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

initial = 11131221131211131231121113112221121321132132211331222113112211

initial = generate_next_key(initial)
print(initial)

initial = generate_next_key(initial)
h = hashlib.sha256()
h.update(str(initial).encode())
key = h.digest()

cipher = AES.new(key, AES.MODE_ECB)
print(cipher.encrypt(pad(flag.encode(),16)).hex())
