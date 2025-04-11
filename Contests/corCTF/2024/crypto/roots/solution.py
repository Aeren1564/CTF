from CTF_Library import *
from decimal import Decimal, getcontext
from Crypto.Util.number import getPrime, bytes_to_long
from output import ct

assert len(ct) == 4

"""
ai, bi, ci in [0, 2**64]
concatenate a0 xor b0 xor c0, a1 xor b1 xor c1, a2 xor b2 xor c2, a3 xor b3 xor c3 to recover flag
ct0 = a0 * sqrt(p) + b0 * sqrt(q) + c0 * sqrt(r)
ct1 = a1 * sqrt(p) + b1 * sqrt(q) + c1 * sqrt(r)
ct2 = a2 * sqrt(p) + b2 * sqrt(q) + c2 * sqrt(r)
ct3 = a3 * sqrt(p) + b3 * sqrt(q) + c3 * sqrt(r)
"""

shift = 2**2024
ct_shifted = [int(x * shift) for x in ct]
mat = matrix(ZZ, 0, 5)
for i in range(4):
	mat = mat.stack(vector(ZZ, [0] * i + [1] + [0] * (3 - i) + [ct_shifted[i]]))

bound = 2**900
lowerbound = [0, 0, 0, 0, 0]
upperbound = [bound, bound, bound, bound, 0]

coef = solve_inequality_with_CVP(mat, lowerbound, upperbound)[ : -1]

print(f"{coef = }")

a = []
for i in range(3):
	# coef0 * a0 + coef1 * a1 + coef2 * a2 + coef3 * a3 = 0
	mat = matrix(ZZ, 0, 5)
	for j in range(4):
		mat = mat.stack(vector(ZZ, [0] * i + [1] + [0] * (3 - i) + [coef[i]]))

	lowerbound = [0, 0, 0, 0, 0]
	upperbound = [2**64, 2**64, 2**64, 2**64, 0]

	a.append(solve_inequality_with_CVP(mat, lowerbound, upperbound)[: -1])
	print(f"{a[-1] = }")
