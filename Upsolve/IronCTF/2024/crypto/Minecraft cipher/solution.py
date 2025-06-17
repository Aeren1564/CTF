from multiprocessing import Pool
import itertools
import os

x = 9014855307380235246

with open('flag.enc', 'rb') as f:
	enc = f.read()
	start = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]
	output = []
	for i in range(0, 8, 2):
		assert 0 <= enc[i] ^ start[i] < 2**7 and 0 <= enc[i + 1] ^ start[i + 1] < 2**7
		output.append((enc[i] ^ start[i]) + (enc[i + 1] ^ start[i + 1]) * 2**7)
		assert 0 <= output[-1] < 2**14

	def check(inp):
		alast, blast = inp
		q = [(9, alast, blast)]
		while len(q) != 0:
			l, alast, blast = q[-1]
			q.pop()
			if l == 23:
				return True, alast, blast
			for i in range(2):
				for j in range(2):
					a = alast | i << l
					b = blast | j << l
					cur = x & 2**(l + 1) - 1
					for k in range(4):
						cur = a * cur + b & 2**(l + 1) - 1
						if cur >> 9 & 2**(l - 8) - 1 != output[k] & 2**(l - 8) - 1:
							break
					else:
						q.append((l + 1, a, b))
		return False, alast, blast

	a, b = None, None
	with Pool(os.cpu_count()) as pool:
		for resp, _a, _b in pool.imap_unordered(check, itertools.product(range(2**9), range(2**9))):
			if resp:
				pool.terminate()
				a, b = _a, _b
				break
	print(f"{a = }, {b = }")
	flag = [x for x in enc]
	for i in range(0, len(enc), 2):
		x = (a * x + b) % 2**23
		flag[i] ^= int(bin(x)[2:].zfill(32)[-16:-9],2)
		if i + 1 < len(enc):
			flag[i + 1] ^= int(bin(x)[2:].zfill(32)[-23:-16],2)
	with open('flag.png', 'wb') as g:
		g.write(bytes(flag))
