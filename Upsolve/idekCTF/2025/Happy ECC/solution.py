from CTF_Library import *

with remote("happy-ecc.chal.idek.team", 1337) as io:
	solve_google_PoW(io)
	cmd = io.readlineS().strip()
	tail = ast.literal_eval(cmd.split(" + ")[1].split(")")[0])
	goal = cmd.split(" = ")[1]
	def solve_PoW(rem):
		for n in range(rem, 2**28, os.cpu_count()):
			if hashlib.md5(str(n).encode() + tail).hexdigest() == goal:
				return n
	with ProcessPoolExecutor(os.cpu_count()) as executor:
		for n in executor.map(solve_PoW, range(os.cpu_count())):
			if n != None:
				io.sendlineafter(b": ", str(n).encode())
				break
	print(f"PoW Done")

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
