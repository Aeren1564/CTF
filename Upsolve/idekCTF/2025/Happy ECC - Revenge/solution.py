from CTF_Library import *

with remote("happy-ecc-revenge.chal.idek.team", 1337) as io:
	solve_google_PoW(io)
	p = int(io.readlineS().strip().split(" = ")[1])
	R, x = PolynomialRing(GF(p), 'x').objgen()
	Us, Vs = [], []
	for _ in range(3):
		io.sendlineafter(b"> ", b"1")
		io.readline()
		U = eval(io.readlineS().split(" = ")[1].replace("^", "**"))
		V = eval(io.readlineS().split(" = ")[1].replace("^", "**"))
		Us.append(U)
		Vs.append(V)
	f = CRT([x**2 for x in Vs], Us)
	print(f"{f = }")
	io.sendlineafter(b"> ", b"2")
	io.sendline(str(HyperellipticCurve(f).zeta_function().numerator()(1)).encode())
	print(io.readallS(timeout = 1))
