from CTF_Library import *
import random

with open("output.txt", 'r') as f:
	out = f.read().strip()

breaker = mersenne_twister_breaker()
breaker.init_byteseed()

for i, b in enumerate(out):
	print(f"{i = }")
	breaker.setrandbits(1, int(b))

print(breaker.recover())
