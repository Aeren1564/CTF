from CTF_Library import *

for _ in range(20):
	x = random.getrandbits(53)
	print(factor(x))