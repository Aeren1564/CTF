from CTF_Library import *
from itertools import chain
import copy

set_random_seed(1337)

p = 18315300953692143461
F = FiniteField(p**3, 'z')

a, b = F.random_element(), F.random_element()
z = F.gen()

output = [50, 32, 83, 12, 49, 34, 81, 101, 46, 108, 106, 57, 105, 115, 102, 51, 67, 34, 124, 15, 125, 117, 51, 124, 38, 10, 30, 76, 125, 27, 89, 14, 50, 93, 88, 56]
#output = [85, 0, 31, 48, 91, 33, 66, 0, 81, 0, 90, 4, 53, 74, 15, 95, 46, 84, 78, 11, 60, 16, 67, 105, 67, 80, 24, 121, 58, 120, 83, 120, 125, 26, 86, 5]

n = len(output) // 3
print(f"{n = }")

K = [b]
for i in range(1, n):
	K.append(K[-1] + b * a**i)
K = [int(x) for x in chain.from_iterable([list(x) for x in K])]

truncated = [(x * 2**57 - K[i]) % p for i, x in enumerate(output)]

res = solve_truncated_homogeneous_LCG(list(a), p, truncated, list(F.gen().minpoly()))
res = [Integer(res[i] + K[i]) + Integer(res[i + 1] + K[i + 1]) * z + Integer(res[i + 2] + K[i + 2]) * z * z for i in range(0, 3 * n, 3)]

for i in range(n - 1):
	assert a * res[i] + b == res[i + 1]

while True:
	myoutput = [int(x) >> 57 for x in chain.from_iterable(list(y) for y in res)]
	print(f"{output = }")
	print(f"{myoutput = }")
	print()
	if output == myoutput:
		break

	output2 = [x - y for x, y in zip(output, myoutput)]

	res2 = solve_truncated_homogeneous_LCG(list(a), p, [(x * 2**57 if x >= 0 else (p + x * 2**57) % p) for x in output2], list(F.gen().minpoly()))
	res2 = [res2[i] + res2[i + 1] * z + res2[i + 2] * z * z for i in range(0, 3 * n, 3)]

	for i in range(n - 1):
		assert a * res2[i] == res2[i + 1]

	for i in range(n):
		res[i] += res2[i]

s = (res[0] - b) / a

print(f"{s = }")

enc_flag = (int(s[0]) + p * int(s[1]) + p * p * int(s[2])).to_bytes(32)
print(f"{enc_flag = }")
flag = "crew{" + enc_flag.decode() + "}"
print(f"{flag = }")