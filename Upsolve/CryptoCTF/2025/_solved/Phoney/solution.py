from CTF_Library import *

nbit = 512
e = 1234567891

while True:
	# with remote("91.107.161.140", 33131) as io:
	with process(["python3", "phoney.py"]) as io:
		io.readlines(5)
		def get_pkey():
			io.readlines(4)
			io.sendline(b"p")
			return [int(io.readlineS().strip().split(" = ")[1]) for _ in "012"]
		def get_enc_flag():
			io.readlines(4)
			io.sendline(b"e")
			return int(io.readlineS().strip().split(" = ")[1])
		n, s, rem = get_pkey()
		p = coppersmith_univariate(n, [0, 1, -s, 1], 2**nbit)[1]
		print(f"{p = }")
		assert is_prime(p) and n % p == 0
		roots = coppersmith_univariate(n // p, [rem, p], 2**64, 2**(512 + (512 >> 3) - 1))
		print(f"{roots = }")
		q = roots[0]
		# x = var("x")
		# roots = cuso.find_small_roots(
		# 	[rem + p * x],
		# 	{x: (2**62, 2**64)},
		# 	modulus = "q",
		# 	modulus_multiple = n // p,
		# 	modulus_lower_bound = 2**(512 + (512 >> 3) - 1)
		# )
		# if len(roots) == 0:
		# 	continue
		# q = roots[0]['q']
		assert is_prime(q) and n % (p * q) == 0
		r = n // (p * q)
		assert is_prime(r)
		enc_flag = get_enc_flag()
		for flag in RSA_decrypt([p, q, r], e, enc_flag):
			flag = long_to_bytes(flag)
			if b"CCTF{" in flag:
				print(f"{flag = }")
				exit()
"""
p - s * p^2 + p^3 = 0 mod n

q = rem + p * x
(rem + p * x) * r = n / p

2/3 vs 3/5
"""