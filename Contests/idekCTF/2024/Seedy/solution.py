from CTF_Library import *
import random

with open("output.txt", 'r') as f:
	out = f.read().strip()

breaker = mersenne_twister_breaker()
breaker.init_byteseed()

for i, b in enumerate(out):
	if i % 1000 == 0:
		print(f"{i = }")
	breaker.setrandbits(1, int(b))

flag = breaker.recover()
print(b"idek{" + flag.split(b"idek{")[1].split(b"}")[0] + b"}")
