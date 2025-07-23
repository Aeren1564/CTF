from CTF_Library import *

q = 256
v = 40
m = 14
F = GF(q)
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

def F2n(x):
	x = list(x)
	return sum(int(x[i]) << i for i in range(8))

with open("output.txt") as file:
	Ms = loads(ast.literal_eval(file.readline().strip().split(" = ")[1]))
	Ps = loads(ast.literal_eval(file.readline().strip().split(" = ")[1]))

for i, (M, P) in enumerate(zip(Ms, Ps)):
	G = M.submatrix(0, 0, v, v)
	H = M.submatrix(0, v, v, m)
	assert G == P.submatrix(0, 0, v, v)
	if (G + G.T).is_invertible():
		S = (G + G.T).inverse() * (P.submatrix(0, v, v, m) - H)
		flag = bytes([F2n(S[i][0]) for i in range(v)])
		print(flag)
		exit()


"""

<makeup(M, n)>
given n by n matrix M over F,
for all j, M[0][j] += M[j][0], then M[j][0] = 0

<mitramap()>
generate length m list of a v+m by v+m matrix where
last m rows are zero
(0, 0) is zero

<embed_secret(msg, v, m)>
embed msg into first row of v by m matrix

<maketrig()>
generate v+m by v+m upper trig matrix
top right v by m matrix is embed_secret(msg, v, m)
"""