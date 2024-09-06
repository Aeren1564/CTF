from out import enc, R
from math import prod

flag = ''

def f(x):
	ret = 0
	while x > 0:
		ret += x % 3
		x //= 3
	return ret

for i in range(355):
    if i%5 == 0:
        flag += chr(enc[i//5] ^ prod([f(_) for _ in R[i//5]]))
        print(flag)
