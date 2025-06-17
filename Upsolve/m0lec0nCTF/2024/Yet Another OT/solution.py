from CTF_Library import *
import json
from Crypto.Cipher import AES
from hashlib import sha256

nc = process(["python3", "server.py"])

print(nc.recvline())
print(nc.recvuntil(b"Send me a number: "))

N, phi = 1, 1
ps = []
for i in range(100):
	p = Primes().unrank(100000 + i)
	N *= p
	phi *= p - 1
	ps.append(p)
d = pow(N, -1, phi)

print(f"{N = }")
nc.sendline(str(N).encode())

ts = []
for tt in json.loads(nc.recvline().decode())["vals"]:
	ts.append(pow(tt, d, N))
key = sha256((",".join(map(str, ts))).encode()).digest()

for _ in range(128):
	json_data = json.loads(nc.recvline().decode())
	c0, c1 = json_data["c0"], json_data["c1"]
	nc.sendline(json.dumps({"m0": int(not all(kronecker(c0, p) == 1 for p in ps)), "m1": int(not all(kronecker(c1, p) == 1 for p in ps))}).encode())

ecflag = bytes.fromhex(nc.recvline().strip().decode())

cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ecflag))

