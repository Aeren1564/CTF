from pwn import *
from Crypto.PublicKey.ECC import EccPoint
from Crypto.Random import random
import time
import hashlib
import json

# AEREN_LOCAL = True
AEREN_LOCAL = False

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
q = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
G = EccPoint(Gx, Gy)

N = 32
T = 64
B = 4

if AEREN_LOCAL:
	nc = process(["python3", "server.py"])
else:
	nc = remote("ecsign.challs.m0lecon.it", 6482)

print(nc.recvline().decode())
bases = eval(nc.recvline().decode().strip())
pk = list(map(int, nc.recvline().decode().strip().split(" ")))

attempt_cnt = 2000
maxv = [-99999] * N

for attempt in range(attempt_cnt):
	nc.sendline(b"1")
	nc.sendline(str(attempt).encode())
print(f"Phase 1 finished")

for attempt in range(attempt_cnt):
	if attempt % 100 == 99:
		print(f"Phase 2 {attempt = }")
	nc.recvuntil(b"The message to sign: ").decode()
	data = json.loads(nc.recvline().decode())
	for t in range(T):
		b, f = data[t]
		if b == 0:
			for i in range(N):
				maxv[i] = max(maxv[i], f[i])

sk = [maxv[i] - N * T * B for i in range(N)]

print(f"{sk = }")

def action(pub, priv):
	res = 1
	for li, ei in zip(bases, priv):
		res = (res * pow(li, ei, q)) % q
	Q = res * pub
	return Q

def sub(a, b):
	return [x-y for x,y in zip(a, b)]

def sign(msg, sk):
	fs = []
	Ps = []
	cnt = 0
	while cnt < T:
		f = [random.randint(-(N*T+1)*B, (N*T+1)*B) for _ in range(N)]
		b = sub(f, sk)
		vec = [-N*T*B <= bb <= N*T*B for bb in b]
		if all(vec):
			P = action(G, f)
			fs.append(f)
			Ps.append((P.x,P.y))
			cnt += 1
	s = ",".join(map(str, Ps)) + "," + msg
	h = int.from_bytes(hashlib.sha256(s.encode()).digest(), "big")
	outs = []
	for i in range(T):
		b = (h>>i) & 1
		if b:
			outs.append((b, sub(fs[i], sk)))
		else:
			outs.append((b, fs[i]))
	return outs

msg = "gimmetheflag"
signed_msg = sign(msg, sk)

print(nc.recvuntil(b">").decode())
nc.sendline(b"2")
print(nc.recvuntil(b"Give me a valid signature: ").decode())
nc.sendline(json.dumps(signed_msg).encode())

print(nc.recvline().decode())
