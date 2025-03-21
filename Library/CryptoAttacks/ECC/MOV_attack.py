# Given are an elliptic curve EC over a finite field, and points P and Q
# Assumes P has low embedding degree (<= 20 to be precise)
# Returns m such that m * P == Q
def MOV_attack(EC, P, Q):
	from sage.all import GF, is_prime
	P, Q = EC(P), EC(Q)
	F = EC.base_field()
	p, k = F.characteristic(), F.degree()
	assert is_prime(p)
	order = P.order()
	for d in range(1, 21):
		if pow(p, k * d, order) == 1:
			break
	else:
		print(f"[ERROR] <MOV_attack> Embedding degree is greater than 20")
		assert False
	print(f"[INFO] <MOV_attack> Embedding degree is {d} and the extension field is of order {p**(k * d)}")
	EC = EC.change_ring(GF(p**(k * d)))
	P = EC(P)
	Q = EC(Q)
	while True:
		R = EC.random_element()
		R = (R.order() // P.order()) * R
		if R.order() == P.order() and R.weil_pairing(P, P.order()) != 1:
			break
	print(f"[INFO] <MOV_attack> {R = }")
	return R.weil_pairing(Q, Q.order()).log(R.weil_pairing(P, P.order()))
