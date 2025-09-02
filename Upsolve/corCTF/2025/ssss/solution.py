from CTF_Library import *

p = 2**255 - 19
k = 15
F = GF(p)

xs = [F(0)]
ys = [F(0)]
with remote("ctfi.ng", 31555) as io:
	io.readline()
	for x in list(range(1, 8)) + list(range(p - 7, p)):
		io.sendline(str(x).encode())
		xs += [F(x)]
		ys += [F(int(io.readlineS().strip()))]
	res = F(0)
	for i in range(k):
		for j in range(k):
			if i == j:
				continue
			cur = ys[j] / (xs[j] - xs[i])
			for m in range(k):
				if m in [i, j]:
					continue
				cur *= -xs[m] / (xs[j] - xs[m])
			res += cur
	io.sendline(str(res).encode())
	print(io.readallS(timeout = 2))
