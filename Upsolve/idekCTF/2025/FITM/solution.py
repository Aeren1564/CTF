from CTF_Library import *

with process(["python3", "server.py"]) as io:
# with remote("fitm.chal.idek.team", 1337) as io:
	rems_list, mods = [], []
	for _ in range(11):
		while True:
			p = getPrime(64)
			if p % 12 == 1:
				break
		io.sendlineafter(b">>> ", b"1")
		io.sendlineafter(b": ", str(p).encode())
		xs = GF(p)(1).nth_root(12, all = True)
		io.sendlineafter(b"> ", ",".join(map(str, xs)).encode())
		io.readuntil(b": ")
		ys = ast.literal_eval(io.readlineS().strip())
		rems_list.append(list(map(int, GF(p)['X'].lagrange_polynomial([(x, y) for x, y in zip(xs, ys)]).coefficients()[5:12])))
		mods.append(p)
	coefs = CRT_coefficients(mods)
	mod = math.prod(mods)
	for i in range(11):
		for j in range(len(rems_list[i])):
			rems_list[i][j] = rems_list[i][j] * coefs[i] % mod
	delta = [[(rems_list[i][(j + 1) % 7] - rems_list[i][j]) % mod for j in range(7)] for i in range(11)]
	def solve_for(i0):
		s = (rems_list[0][i0] + sum(rems_list[t][0] for t in range(1, 11))) % mod
		for i1 in range(7):
			for i2 in range(7):
				for i3 in range(7):
					for i4 in range(7):
						for i5 in range(7):
							for i6 in range(7):
								for i7 in range(7):
									for i8 in range(7):
										for i9 in range(7):
											for i10 in range(7):
												if s.bit_length() <= 640:
													io.sendlineafter(b">>> ", b"2")
													io.sendlineafter(b": ", long_to_bytes(s).hex().encode())
													resp = io.readlineS().strip()
													if resp != "Try harder.":
														print(i0, i1, i2, i3, i4, i5, i6, i7, i8, i9, i10)
														print(resp)
														exit()
												s += delta[10][i10]
												if s >= mod:
													s -= mod
											s += delta[9][i9]
											if s >= mod:
												s -= mod
										s += delta[8][i8]
										if s >= mod:
											s -= mod
									s += delta[7][i7]
									if s >= mod:
										s -= mod
								s += delta[6][i6]
								if s >= mod:
									s -= mod
							s += delta[5][i5]
							if s >= mod:
								s -= mod
						s += delta[4][i4]
						if s >= mod:
							s -= mod
					s += delta[3][i3]
					if s >= mod:
						s -= mod
				s += delta[2][i2]
				if s >= mod:
					s -= mod
			s += delta[1][i1]
			if s >= mod:
				s -= mod
	with ProcessPoolExecutor(os.cpu_count()) as executor:
		for _ in executor.map(solve_for, range(7)):
			pass
