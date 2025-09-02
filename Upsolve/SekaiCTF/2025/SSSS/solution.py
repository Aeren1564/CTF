from CTF_Library import *

p = 2 ** 256 - 189
deg = 29
assert (p - 1) % deg == 0
roots = GF(p)(1).nth_root(deg, all = True)

while True:
	with remote("ssss.chals.sekai.team", 1337, ssl = True) as io:
		polys = []
		for _ in range(2):
			io.sendline(str(deg).encode())
			data = []
			for i in range(deg):
				io.sendline(str(roots[i]).encode())
				data.append((roots[i], GF(p)(io.readlineS().strip())))
			if _ == 0:
				io.sendline(b"0")
				assert io.readlineS().strip() == ":<"
			polys.append(GF(p)['X'].lagrange_polynomial(data))
		cand = polys[0].coefficients()
		for x in polys[1].coefficients():
			if x in cand:
				io.sendline(str(x).encode())
				print(io.readallS(timeout = 1))
				exit()
