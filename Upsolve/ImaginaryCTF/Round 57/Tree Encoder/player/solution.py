from CTF_Library import *

data = [None] * 10
for x in range(10):
	with process(["./tree-encoder", bytes([x])]) as io:
		data[x] = io.readlineS().strip()
for x in range(10):
	print(x, data[x])
