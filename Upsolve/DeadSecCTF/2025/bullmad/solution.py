from CTF_Library import *
from server import sign_with_nonce

EC = fast_secp256k1
G = fast_secp256k1_basepoint
n = fast_secp256k1.order()

assert is_prime(EC.mod)

for attempt in range(10**9):
	print(f"{attempt = }")
	with process(["python3", "server.py"]) as io:
		io.readuntil(b" = ")
		m0 = ast.literal_eval(io.readlineS().strip()).encode()
		io.readuntil(b" = ")
		r0 = int(ast.literal_eval(io.readlineS().strip())) % n
		io.readuntil(b" = ")
		s0 = int(ast.literal_eval(io.readlineS().strip())) % n
		io.readuntil(b" = ")
		v0 = int(ast.literal_eval(io.readlineS().strip()))
		io.readuntil(b" = ")

		m1 = ast.literal_eval(io.readlineS().strip()).encode()
		io.readuntil(b" = ")
		r1 = int(ast.literal_eval(io.readlineS().strip())) % n
		io.readuntil(b" = ")
		s1 = int(ast.literal_eval(io.readlineS().strip())) % n
		io.readuntil(b" = ")
		v1 = int(ast.literal_eval(io.readlineS().strip()))

		io.readuntil(b": ")
		m2 = ast.literal_eval(io.readlineS().strip()).encode()

		e0 = int.from_bytes(hashlib.sha256(m0).digest(), 'big') % n
		e1 = int.from_bytes(hashlib.sha256(m1).digest(), 'big') % n
		e2 = int.from_bytes(hashlib.sha256(m2).digest(), 'big') % n

		R0 = EC.lift_x(r0, v0)
		R1 = EC.lift_x(r1, v1)

		s0inv = pow(s0, -1, n)
		s1inv = pow(s1, -1, n)

		denom = (r1 * s1inv - r0 * s0inv) % n
		denom_inv = pow(denom, -1, n)
		coef_sk0 = ((e0 * s0inv - e1 * s1inv) * denom_inv) % n
		coef_sk1 = (1 * denom_inv) % n
		coef_nonce0 = (e0 * s0inv + coef_sk0 * r0 * s0inv) % n
		coef_nonce1 = (coef_sk1 * r0 * s0inv) % n

		A = R0 - coef_nonce0 * G
		B = coef_nonce1 * G
		block = 2**21
		jump = block * B

		P0 = EC(B.x, B.y)
		P1 = A - jump
		print(f"Constructing buckets")
		found0 = [[] for _ in range(block)]
		found1 = [[] for _ in range(block)]
		# dif is an integer in range [0, 2**64) such that dif * B = A
		print(f"Starting search")
		for i in range(1, block + 1):
			if i % 100000 == 0:
				print(f"{i = }")
			found0[P0.x & block - 1].append(P0.x)
			found1[P1.x & block - 1].append(P1.x)
			if P0.x in found1[P0.x & block - 1]:
				print(f"Found 0")
				P1 = A - jump
				for j in range(1, i + 1):
					if P0 == P1:
						dif = i + block * j
						break
					P1 -= jump
				else:
					assert False
				break
			if P1.x in found0[P1.x & block - 1]:
				print(f"Found 1")
				P0 = Point(B.x, B.y, curve = secp256k1)
				for j in range(1, i + 1):
					if P0 == P1:
						dif = j + block * i
						break
					P0 += B
				else:
					assert False
				break
			P0 += B
			P1 -= jump
		else:
			print(f"Failed :(\n")
			assert False
			continue

		nonce = (coef_nonce0 + dif * coef_nonce1) % n
		sk = (coef_sk0 + dif * coef_sk1) % n

		print(f"{dif = }")
		print(f"{nonce = }")
		print(f"{sk = }")

		assert (r0, s0, v0) == sign_with_nonce(sk, m0, nonce)
		assert (r1, s1, v1) == sign_with_nonce(sk, m1, (nonce + dif) % n)

		r2, s2, v2 = sign_with_nonce(sk, m2, nonce)
		io.sendline(str(r2).encode())
		io.sendline(str(s2).encode())
		print(io.readallS(timeout=1))
		break

"""
G: fixed gen point

nonce: integer in [1, n)
sk: secret key (32 bytes integer)
e0, e1: msg
dif: 64-bit integers
R0 = nonce * G
R1 = (nonce + dif) * G
s0 = (e0 + R0.x * sk) / nonce
s1 = (e1 + R1.x * sk) / (nonce + dif)

Given: e0, R0, s0, e1, R1, s1
goal: given e2, forge R2 and s2 such that
 s2 * R2 = e2 * G + R2.x * sk * G


nonce       = e0 / s0 + R0.x / s0 * sk mod n
nonce + dif = e1 / s1 + R1.x / s1 * sk mod n

nonce = a + b * dif
sk = c + d * dif

a * G + dif * (b * G) == R0

dif * B = A

dif = (e1 / s1 - e0 / s0) + (R1.x / s1 - R0.x / s0) * sk mod n
sk = 1 / (R1.x / s1 - R0.x / s0) * dif + (e0 / s0 - e1 / s1) / (R1.x / s1 - R0.x / s0)



s0 * R0 = e0 * G + R0.x * sk * G
s1 * R1 = e1 * G + R1.x * sk * G
s2 * R2 = e2 * G + R2.x * sk * G

"""