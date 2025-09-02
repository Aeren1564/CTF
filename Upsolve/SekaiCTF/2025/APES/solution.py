from CTF_Library import *

F = GF(256)
R = F["k0, k1, k2, k3, k4, k5, k6, k7"]
Q = QuotientRing(R, Ideal([x**256 + x for x in R.gens()]))
k = Q.gens()
print(f"{Q = }")
print(f"{k = }")

def to_F(x):
	return F([x >> i & 1 for i in range(8)])

def to_int(x):
	x = list(x)
	return sum(int(x[i]) << i for i in range(8))

perm = [to_int(to_F(x)**254) for x in range(256)]

with process(["python3", "chall.py"]) as io:
	trial = 0
	while True:
		trial += 1
		print(f"{trial = }")
		io.sendlineafter(b"Plainperm: ", bytes(perm).hex().encode())
		io.readuntil(b"Cipherperm: ")
		cipherperm = list(bytes.fromhex(io.readlineS().strip()))
		io.readline()
		polys = []
		for i in range(8):
			poly = to_F(i)
			for j in range(8):
				poly += k[j]
				if j < 7:
					poly = poly**3
			poly -= to_F(cipherperm[i])
			print(f"{poly = }")
			polys.append(poly)
		basis = Ideal(polys).groebner_basis()
		print(f"{basis = }")
		print(f"{list(basis) = }")
		if basis != [Q(1)]:
			assert len(basis) == 8
			print(f"Nno-trivial basis {basis}")
			value = [None for _ in range(8)]
			for poly in basis:
				terms = poly.terms()
				assert terms[0].degree() == 1
				for i in range(8):
					if terms[0] == k[i]:
						values[i] = to_int(list(terms[1])[0])
						break
				else:
					assert False
			assert all(x != None for x in value)
			io.sendline(bytes(value).hex().encode())
			print(io.readlineS())
			exit()
		io.sendline(b"")
		assert io.readline() == b"Bad luck, try again.\n"
		print()

"""


"""
