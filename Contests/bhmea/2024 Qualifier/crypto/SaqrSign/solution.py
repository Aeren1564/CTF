from CTF_Library import *
from random import Random

rng = Random()

N, Q, W, P = 1024, 12289, 4324, 9389
Zn = Zmod(Q)

D = [Zn(rng.randint(-1, 1)) for _ in range(N)]
G = [Zn(rng.randint(-1, 1)) for _ in range(N)]
print(f"{D = }")
print(f"{G = }")

E = [Zn(rng.randrange(0, Q)) for _ in range(N)]
A = [Zn(0) for i in range(N)]
for i in range(N):
	A[i] = -D[i]
	for j in range(N):
		A[i] += G[j] * E[(i - j) % N]

mat = []
for i in range(2 * N):
	row = [0] * (3 * N)
	row[i] = 1
	if i < N:
		row[2 * N + i] = -1
	mat.append(row[ : ])
for j in range(N):
	for i in range(N):
		mat[N + i][2 * N + j] = E[(j - i) % N]
for i in range(N):
	row = [0] * (3 * N)
	row[2 * N + i] = Q
	mat.append(row[ : ])
lowerbound, upperbound = [-1] * (3 * N), [1] * (3 * N)
for i in range(N):
	lowerbound[2 * N + i] = upperbound[2 * N + i] = int(A[i])

ret = solve_inequality_with_CVP(mat, lowerbound, upperbound)
DD, GG = ret[ : N], ret[N : 2 * N]
print(f"{DD = }")
print(f"{GG = }")
assert DD == [int(x) for x in D]
assert GG == [int(x) for x in G]
