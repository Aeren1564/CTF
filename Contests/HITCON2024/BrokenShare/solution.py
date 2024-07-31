# Stream Ciphers: ChaCha20
# Block Ciphers: AES
from Crypto.Cipher import AES, ChaCha20
# sha256
from hashlib import *
# pad
from Crypto.Util.Padding import *
from Crypto.Util.number import *
import math
import os
import zlib
import string
from typing import List
from sage.all import *

p = 65537

# in ascii order
flag_char_pool = string.digits + string.ascii_uppercase + '_' + string.ascii_lowercase

# Source: https://github.com/rkm0959/Inequality_Solving_with_CVP/blob/main/solver.sage
def solve_inequality_with_CVP(M, lbounds, ubounds, weight = None):
	from sage.modules.free_module_integer import IntegerLattice

	# Directly taken from rbtree's LLL repository
	# From https://oddcoder.com/LOL-34c3/, https://hackmd.io/@hakatashi/B1OM7HFVI
	def Babai_CVP(mat, target):
		M = IntegerLattice(mat, lll_reduce=True).reduced_basis
		G = M.gram_schmidt()[0]
		diff = target
		for i in reversed(range(G.nrows())):
			diff -=  M[i] * ((diff * G[i]) / (G[i] * G[i])).round()
		return target - diff

	mat, lb, ub = copy(M), copy(lbounds), copy(ubounds)
	num_var  = mat.nrows()
	num_ineq = mat.ncols()

	max_element = 0 
	for i in range(num_var):
		for j in range(num_ineq):
			max_element = max(max_element, abs(mat[i, j]))

	if weight == None:
		weight = num_ineq * max_element

    # sanity checker
	if len(lb) != num_ineq:
		print("Fail: len(lb) != num_ineq")
		return

	if len(ub) != num_ineq:
		print("Fail: len(ub) != num_ineq")
		return

	for i in range(num_ineq):
		if lb[i] > ub[i]:
			print("Fail: lb[i] > ub[i] at index", i)
			return

    	# heuristic for number of solutions
	DET = 0

	if num_var == num_ineq:
		DET = abs(mat.det())
		num_sol = 1
		for i in range(num_ineq):
			num_sol *= (ub[i] - lb[i])
		if DET == 0:
			print("Zero Determinant")
		else:
			num_sol //= DET
			# + 1 added in for the sake of not making it zero...
			print("Expected Number of Solutions : ", num_sol + 1)

	# scaling process begins
	max_diff = max([ub[i] - lb[i] for i in range(num_ineq)])
	applied_weights = []

	for i in range(num_ineq):
		ineq_weight = weight if lb[i] == ub[i] else max_diff // (ub[i] - lb[i])
		applied_weights.append(ineq_weight)
		for j in range(num_var):
			mat[j, i] *= ineq_weight
		lb[i] *= ineq_weight
		ub[i] *= ineq_weight

	# Solve CVP
	target = vector([(lb[i] + ub[i]) // 2 for i in range(num_ineq)])
	result = Babai_CVP(mat, target)

	for i in range(num_ineq):
		if (lb[i] <= result[i] <= ub[i]) == False:
			print("Fail : inequality does not hold after solving")
			break
    
    	# recover x
	fin = None

	if DET != 0:
		mat = mat.transpose()
		fin = mat.solve_right(result)
	
	## recover your result
	return result, applied_weights, fin

n, t = 48, 24

ct = b'^\xc0dgy\x86U\xf1\x81\xedT\x9c\xfa\xa9\x12zN\xa4r;\xad\x8e\x90\x90\xc1'
shares = [(1565, 19863), (30094, 10609), (22274, 52704), (1784, 985), (63428, 28511), (33493, 36637), (64170, 4165), (45290, 18327), (48817, 15661), (27252, 46373), (250, 795), (461, 50126), (61643, 56440), (43533, 49383), (57090, 57452), (10759, 36118), (50541, 6206), (38042, 61005), (11746, 53527), (18804, 64250), (6544, 13381), (42788, 43622), (27190, 15260), (6963, 9736), (58058, 4896), (44681, 26415), (37909, 41980), (11928, 37989), (48296, 59096), (24600, 5260), (15269, 40953), (62949, 55091), (34338, 12278), (39083, 886), (46514, 63236), (59867, 4707), (54080, 56612), (21643, 5325), (52919, 58089), (2661, 4072), (15248, 14956), (7875, 7978), (57249, 19124), (32741, 8715), (14204, 41429), (48336, 41391), (52577, 54499), (49572, 25959)]

xs, ys = zip(*shares)

M = Matrix(5 * t, 5 * t)
lbounds = [0] * (5 * t)
ubounds = [0] * (5 * t)
for j in range(n):
	for i in range(t):
		M[i, j] = pow(xs[j], i, 1 << 32)
	M[t + j, j] = p
	M[n + t + j, j] = 1 << 32
	lbounds[j] = ys[j]
	ubounds[j] = ys[j]
for j in range(n, n + t):
	M[j - n, j] = 1
	lbounds[j] = 0
	ubounds[j] = p
for j in range(n + t, 2 * n + t):
	M[j - n, j] = 1
	lbounds[j] = 0
	ubounds[j] = ((1 << 32) + p - 1) // p

ret = solve_inequality_with_CVP(M, lbounds, ubounds)

assert ret != None

result, applied_weights, fin = ret

ks = []
for x in range(t):
	res = 0
	for c in fin[ : n]:
		res = x * res + c
	ks.append(res % p)

key = sha256(repr(ks).encode()).digest()
cipher = AES.new(key, AES.MODE_CTR, nonce=ct[:8])
print(cipher.decrypt(ct[8:]))