from sage.all import *
proof.all(False)
from CTF_Library import *
from output import blocklen, n, pol, c
from hashlib import sha256
from Crypto.Cipher import AES

K = Zmod(n)
PR, (v, w, x, y, z) = K["v, w, x, y, z"].objgens()

coef = [0] * 3**5

for i in range(3):
	for j in range(3):
		for k in range(3):
			for l in range(3):
				for m in range(3):
					coef[3**4 * i + 3**3 * j + 3**2 * k + 3**1 * l + 3**0 * m] = int(pol.coefficient({a : b for a, b in zip([v, w, x, y, z], [i, j, k, l, m])}))

mat = block_matrix([
	[
		identity_matrix(ZZ, 3**5),
		matrix(ZZ, coef).T
	],
	[
		zero_matrix(ZZ, 1, 3**5),
		matrix(ZZ, [n])
	]
])

lower_bound = [1] + [0] * (3**5 - 1) + [0]
upper_bound = [0] * 3**5 + [0]
for i in range(3):
	for j in range(3):
		for k in range(3):
			for l in range(3):
				for m in range(3):
					upper_bound[3**4 * i + 3**3 * j + 3**2 * k + 3**1 * l + 3**0 * m] = 256**(30 * (i + j + k + l + m))

values = solve_inequality_with_CVP(mat, lower_bound, upper_bound)

print(f"{values = }")

key = bytearray()
for x in [values[3**4], values[3**3], values[3**2], values[3**1], values[3**0]]:
	print(f"{x = }")
	key.extend(int(x).to_bytes(30))

print(f"{key = }")

key = sha256(key).digest()
cipher = AES.new(key, AES.MODE_ECB)
flag = cipher.decrypt(bytes.fromhex(c))
print(f"{flag = }")
