#!/usr/bin/env sage

from flag import flag

q, v, m = 256, 40, 14
_F = GF(q)

def makeup(M, n):
	for i in range(n):
		for j in range(i, n):
			M[i, j] += M[j, i]
			M[j, i] = 0
		return M

def mitramap():
	_M = []
	for s in range(m):
		M = zero_matrix(_F, v + m, v + m)
		for i in range(0, v):
			M[i, (i + s + 1) % v] = _F.random_element()
			M[i, (i + s) % m + v] = _F.random_element()
		M = makeup(M, v + m)
		_M.append(M)
	return _M

def n2F(n):
	x = _F.gen()
	e = sum(((n >> _) & 1) * x ** _ for _ in range(8))
	return e

def embed_secret(msg, v, m):
	M = random_matrix(_F, v, m)
	for _ in range(v):
		M[_, 0] = n2F(msg[_])
	return M

def maketrig():
	return block_matrix([
		[identity_matrix(_F, v), embed_secret(flag, v, m)],
		[zero_matrix(_F, m, v), identity_matrix(_F, m)]
	])

def makepub(F, S):
	S = S.submatrix(0, v, v, m)
	return [
		block_matrix([
			[
				G := M.submatrix(0, 0, v, v),
				(G + G.transpose()) * S + (H := M.submatrix(0, v, v, m))
			],
			[
				zero_matrix(_F, m, v),
				makeup(S.transpose() * G * S + S.transpose() * H, m)]
		])
		for M in F[:m]
	]

F, S = mitramap(), maketrig()
P = makepub(F, S)

print(f'{dumps(F) = }')
print(f'{dumps(P) = }')