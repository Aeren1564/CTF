from CTF_Library import *

with process(["python3", "chall.py"]) as io:
	def interact(length):
		io.sendlineafter(b"Yes? ", b"yes")
		io.sendlineafter(b"Length: ", str(length).encode())
		io.readuntil(b": ")
		a = int(io.readlineS().strip())
		io.readuntil(b": ")
		b = int(io.readlineS().strip())
		c, d, e = map(int, io.readlineS().strip().split(" "))
		assert c == 0 and d == 65537
		return a, b, int(isqrt(e))
	flag_len = partition_point(2, 10000, lambda x: interact(x)[2] != 256) // 40
	flag_popcount = interact(10000)[1] - math.ceil(10000 / 8) * ord("a").bit_count()
	print(f"{flag_len = }")
	r, m = 0, 1
	primes = []
	for p in Primes():
		if p >= 256:
			break
		if p >= 3:
			primes.append(p)
	while True:
		append_len_base = 1 + math.ceil(primes[0].bit_length() / 8)
		extra_base = 256**append_len_base // 255 * ord("a")
		print(f"{primes = }")
		while True:
			width_base, count_base, p = interact(primes[0].bit_length())
			if p in primes:
				primes.pop(primes.index(p))
				break
		print(f"{p = }")
		count = []
		for i in range(1, 100, 8):
			w, c, _p = interact(10000 + i)
			assert p == _p
			count.append(c)
		for rem in range(p):
			exp_base = (rem * 256**append_len_base + extra_base) // p
			for i in range(1, 100, 8):
				append_len = 1 + math.ceil((10000 + i) / 8)
				extra = 256**append_len // 255 * ord("a")
				exp = (rem * 256**append_len + extra) // p
				if exp_base.bit_count() - exp.bit_count() != count_base - count[i // 8]:
					break
			else:
				break
		else:
			assert False
		print(f"{rem = }")
		r = CRT([rem, r], [p, m])
		m *= p
		print(f"{r = }, {m = }")
		if m.bit_length() >= 8 * flag_len:
			break
	print(long_to_bytes(r))
