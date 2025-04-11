from Crypto.Cipher import AES
from hashlib import sha256

pt = bytes.fromhex("4145535f4145535f4145535f41455321")
ct = bytes.fromhex("edb43249be0d7a4620b9b876315eb430")
enc_flag = bytes.fromhex("e5218894e05e14eb7cc27dc2aeed10245bfa4426489125a55e82a3d81a15d18afd152d6c51a7024f05e15e1527afa84b")

chars = b'crew_AES*4=$!?'
L = 3

pool = []
for a in chars:
	for b in chars:
		for c in chars:
			x = bytes([a, b, c])
			pool.append((sha256(x).digest(), x))

half = {}
for k1, w in pool:
	pt2 = AES.new(k1, AES.MODE_ECB).encrypt(pt)
	for k2, x in pool:
		half[AES.new(k2, AES.MODE_ECB).encrypt(pt2)] = (w, x)

print(f"{len(half) = }")

res = []
for k4, z in pool:
	pt2 = AES.new(k4, AES.MODE_ECB).decrypt(ct)
	for k3, y in pool:
		pt3 = AES.new(k3, AES.MODE_ECB).decrypt(pt2)
		if pt3 in half:
			res = list(half[pt3]) + [y, z]
			break
	if res:
		break

print(f"{res = }")

print(AES.new(sha256(res[0] + res[1] + res[2] + res[3]).digest(), AES.MODE_ECB).decrypt(enc_flag))