from CTF_Library import *
import random
import time

with remote("challs.pwnoh.io", 13421) as io:
	io.readline()
	n = eval(io.readline().split(b" ")[-1])
	y = eval(io.readline().split(b" ")[-1])
	io.readline()
	x = -1
	t = int(time.time())
	while True:
		random.seed(t)
		x = random.randrange(1, n)
		if x * x % n == y:
			break
		t -= 1
	random.seed(0)
	for _ in range(128):
		z = random.randrange(1, n)
		io.sendlineafter(b": ", str(z * z % n).encode())
		b = eval(io.readline().split(b" ")[-1])
		if b == 0:
			z = z * x % n
		io.sendlineafter(b": ", str(z).encode())
		print(io.readlineS())
	print(io.readallS(timeout = 2))
