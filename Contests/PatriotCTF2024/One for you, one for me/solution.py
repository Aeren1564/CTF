from CTF_Library import *
import string

with open("output.txt", 'r') as f:
	n = 296
	mat = matrix(ZZ, 0, n)
	value = []
	for s in f.read().split("\n")[ : 3 * n]:
		s = bin(int(s, 16))[2 : ].zfill(n)
		mat = mat.stack(vector(ZZ, [1 if c == '1' else -1 for c in s]))
		value.append(n // 2 - sum([c == '0' for c in s]))
	print(f"{mat.dimensions() = }")
	print(f"{len(value) = }")
	assignment = mat.solve_right(vector(ZZ, value))
	print(f"{assignment = }")
	assert min(assignment) == 0 and max(assignment) == 1
	for _ in range(2):
		flag = ""
		for i in range(n):
			flag += str(assignment[i])
		print(bytes([int(flag[i : i + 8], 2) for i in range(0, n, 8)]))
		assignment = [1 - x for x in assignment]
