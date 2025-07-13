#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

def makecore(B, E):
	_B = list(B) 
	while len(_B) < E.dimension():
		b = E.random_element() 
		if not _B and b.is_zero():
			continue 
		if b not in E.span(_B):
			_B.append(b) 
	return _B

def genkey(q, k, v):
	n = k + v 
	FF = GF(q)
	M = matrix(FF, makecore([], FF ** n))
	F, pkey = [], []
	for _ in range(k):
		while True:
			A, B = matrix(FF, k, k), random_matrix(FF, k, v)
			C, D = random_matrix(FF, v, k), random_matrix(FF, v, v)
			E = block_matrix([[A, B], [C, D]])
			if E.is_invertible():
				break
		if FF.characteristic() != 2: 
			E = FF(2) ** (-1) * (E + E.transpose())
		G = M.transpose() * E * M
		F.append(E)
		pkey.append(G)
	skey = (M, F)
	return skey, pkey

def sign(skey, G):
	while True:
		M, F = skey
		q = M.base_ring().cardinality()
		k = len(F)
		n = F[0].dimensions()[0]
		v = n - k
		_M = M.inverse()
		FF = GF(q)
		RR = PolynomialRing(FF, 'x', k)
		X = RR.gens()
		Y = vector(RR, list(X) + [FF.random_element() for _ in range(v)])
		E = [Y * F[e] * Y for e in range(k)]
		C = [[E[i].coefficient(X[j]) for j in range(k)] for i in range(k)]
		S = matrix(FF, C)
		B = vector([eq([0] * k) for eq in E]) 
		T = G - B
		try:
			_S = S.solve_right(T)
			V = vector(FF, list(_S) + list(Y[k:])) 
			return _M * V
		except:
			continue			

def vecsub(skey):
	A, F = skey
	V = span(A.inverse().columns()[:len(F)])
	return V.random_element()

q, m, v = 256, 40, 64
skey, pkey = genkey(q, m, v)
A, F = skey
M = bytes_to_long(flag)
l = M.bit_length()
FLAG_BITS = [int(_) for _ in list(bin(M)[2:])]

SIGNS = []
for i in range(len(FLAG_BITS)) :
	if FLAG_BITS[i] :
		SIGNS.append(vecsub(skey))
	else :
		SIGNS.append(sign(skey, vector([randint(0, 1) for _ in range(m)])))

f = open('signatures.txt', 'w')
f.write(str(SIGNS))
f.close()