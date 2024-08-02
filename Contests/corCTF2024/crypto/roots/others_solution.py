from sage.all import *
from Crypto.Util.number import long_to_bytes
from itertools import product, permutations
from functools import reduce
from operator import xor

R = RealField(6724)
Decimal = R # for eval
with open('output.txt', 'r') as f:
    hints = eval(f.read())

n = len(hints)
L = block_matrix(QQ, [
    [column_matrix(hints), identity_matrix(n)],
])
# weight matrix
W = diagonal_matrix([2**2048] + [1]*n)

# small linear combination, ~187 bits each
# the first vector is always the shortest
v = ((L*W).LLL() / W)[0][1:] 
ker = matrix(ZZ, v).right_kernel_matrix(basis='LLL')

possible_cols = []
for coord in product(range(-3, 3), repeat=ker.nrows()):
    v = vector(ZZ, coord) * ker
    if all(0 <= x <= 2**64 for x in v): # known bounds on our input
        possible_cols.append(v)

seen = set()
found = False
for cols in permutations(possible_cols, r=3):
    for row in [*zip(*cols)]:  # transpose
        res = long_to_bytes(reduce(xor, row))
        if all(32 <= x < 127 for x in res) and res not in seen: # printable
            if b'corctf{' in res: found = True
            seen.add(res)
            print(end=res.decode())
    if found: break

# corctf{I'm_r00t1ng_f0R_U!!!!!!!}

# Small explanation:
# The secret we seek consist of 4*3 numbers, we can arrange this into a matrix
# A = [
#  [a0, b0, c0],
#  [a1, b1, c1],
#  [a2, b2, c2],
#  [a3, b3, c3],
# ]
# (c0...c3 is the padded message, a and b contain the padding values)
# We are given A*[sqrts of primes].
# Since there is no small linear combination between the primes which equals 0
# (they are irrational (in theory)) if we ask LLL to find an approximate solution to
# h dot x = 0, where h is the hints we are given, then LLL will instead find a solution
# to ((a dot x = 0) and (b dot x = 0) and (c dot x = 0)), which is possible since they
# are integers and relatively small.
# 
# We thus have a vector v such that v*A = 0, which means v is orthogonal to every column of A,
# hence the kernel of v as a row matrix contains all the columns of A.
# Since the columns of A are small they will be small linear combinations of the LLL
# reduced basis of ker(v), we can do a little ugly enumeration to find them.