from CTF_Library import *

nbit = 110
prec = 4 * nbit
R = RealField(prec)

#with process(["sage", "vainrat.sage"]) as io:
with remote("91.107.252.0", 11117) as io:
	io.readuntil(b"y0 = ")
	y0 = R(io.readlineS().strip())
	y = y0
	c = 0
	print(f"{c = }")
	print(f"{y = }")
	print()
	log = {c: y}
	while True:
		c += 1
		print(f"{c = }")
		io.readlines(3)
		io.sendline(b"c")
		resp = io.readlineS().strip()
		if resp == "┃ Unfortunately, the rat got away :-(":
			y = None
		else:
			z = R(resp.split(" = ")[1].strip())
			log[c] = z
			if y == None:
				y = z
				continue
			x = z**2 * 2 / y - y
			print(f"Initial {c = }")
			print(f"{x = }")
			print(f"{y = }")
			assert x < y
			c -= 1
			while c > 0:
				c -= 1
				if c in log:
					y = log[c]
				else:
					y = y**2 / x
				x = 2 * x - y
				print(f"Reverted to {c = }")
				print(f"{x = }")
				print(f"{y = }")
				assert x < y
			# Repeat lots of times and print common prefix
			break

"""
x, y
(x+y)/2, y
(x+y)/2, sqrt((x+y)*y/2)


x, y**2 / x
x, y

0.678476115854709485500044951354299580150888171940281786813194398218373542184809765526189109749723424080338331287485227389058190262713
0.678476115854709485500044951354299580150888171940281786813194398218373542184809765526189109749723424080338331287485227389014661038107
0.678476115854709485500044951354299580150888171940281786813194398218373542184809765526189109749723424080338331287485227389000066750946
"""