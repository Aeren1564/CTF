from CTF_Library import *

with open("output.raw", "rb") as file:
	poly = loads(file.read())

data = []
for x in range(-1, -1000, -1):
	y = poly(x)
	if y in ZZ and 0 <= y < 256:
		data.append((x, int(y)))

flag_len = len(data)
flag = [0] * flag_len
for x, y in data:
	n = (-x - 1 + 14) * pow(19, -1, flag_len)
	flag[(63 * n - 40) % flag_len] = y
print(bytes(flag))