from CTF_Library import *

B = 5
n = 19
D = 110
t = 128
l = 4 * D * B // t
tot = l * t // 2

with remote("91.107.132.34", 31131) as io:
	io.readlines(4)
	data = []
	for _ in range(10):
		io.readlines(4)
		io.sendline(b"m")
		for i in range(0, l * t // 2, 16):
			cur = ast.literal_eval(io.readlineS().strip()[2:].replace(" ", ", "))
			assert len(cur) == 16
			data += cur
	key = [0] * n
	for pos in range(n):
		cnt = [0] * (2 * B * (D + 1) + 1)
		for row in data:
			cnt[row[pos]] += 1
		window_cnt = [0] * (2 * B + 1)
		for k in range(-B, B + 1):
			for x in range(k - B * D, k + B * D + 1):
				window_cnt[k] += cnt[x]
		key[pos] = window_cnt.index(tot * 10)
		if key[pos] > B:
			key[pos] -= 2 * B + 1
	io.readlines(4)
	io.sendline(b"g")
	io.readline()
	io.sendline(str(key)[1:-1].encode())
	print(io.readallS(timeout = 1))

"""
B = 5
n = 19
D = 110
t = 128
l = floor(4 * D * B / t) = 17
l * t // 2 = 1088

randroad(x): generates a random int vector with value range [-x, x]
roadband(): generates a random int vector with value range [B * (D+1)]
key <- randroad(B)
silky(key) <- roadband() where both min and max of silky(key) - key is out of range [-B * D, B * D]

"""