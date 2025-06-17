from CTF_Library import *

outputs = bytes.fromhex("672c81f887ac08cebf06b106114563695a14ce1717fa3973bc6b1d810ad25c3c")
enc_flag = bytes.fromhex("5c285fcff21cadb30a6ec92d445e5d75898f83fc31ff395cb43fb8be319d464895cf9aed809c20f92eb6f79f6bd36fc8d3091725b54c889a22850179ec26f89c")
assert len(outputs) == 32

size = 2**53
base = 2**(512 - 53)

outputs = [bytes_to_long(outputs[i : i + 8]) * pow(base, -1, 2**64 - 59) % (2**64 - 59) for i in range(0, len(outputs), 8)]
assert all(0 <= x < size for x in outputs)
for x in outputs:
	print(f"{bin(x) = }")
	cnt = 0
	while x % 5 == 0:
		cnt += 1
		x //= 5

m = 2
for p in Primes():
	if p == 2 or p == 5:
		continue
	pw = p
	while all((outputs[i] * outputs[i + 2] - outputs[i + 1]**2) % pw == 0 for i in range(2)):
		print(f"Sucess {pw = }")
		m *= p
		pw *= p
"""
K = 2**(512 - 53)
s K*a*s K*a*K*a*s 
"""