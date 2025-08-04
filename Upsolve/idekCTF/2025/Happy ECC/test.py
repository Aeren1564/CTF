from CTF_Library import *
from chall import HyperellipticCurve_

p = getPrime(40)
R, x = PolynomialRing(GF(p), 'x').objgen()

f = R.random_element(5).monic()
H = HyperellipticCurve_(f)

P = H.random_element()
Q = H.random_element()
R = H.random_element()

print(f"{P.U = }")
print(f"{P.V = }")
print(f"{Q.U = }")
print(f"{Q.V = }")
print(f"{R.U = }")
print(f"{R.V = }")

assert P.V**2 % P.U == f % P.U
assert Q.V**2 % Q.U == f % Q.U
assert R.V**2 % R.U == f % R.U
assert (P + Q) + R == P + (Q + R)

H = HyperellipticCurve(f)

J = H.jacobian()

M = H.zeta_function().numerator()(1)
print(f"{M = }")

# Frob = H.frobenius_polynomial()  # returns F(X) of degree 4
# # and the relationship is P(T)=T^4*F(1/T), so you can also do:
# P = T^4 * Frob(1/T)              
# order = P(1)
# print(order)

# for u, v in [[P.U, P.V], [Q.U, Q.V], [R.U, R.V]]:
# 	D = J(u, v)
# 	print(D.order())
