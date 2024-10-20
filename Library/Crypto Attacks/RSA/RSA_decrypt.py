def RSA_decrypt(enc : int, p : int, q : int, e : int):
	from Crypto.Util.number import inverse, isPrime
	assert isPrime(p) and isPrime(q) and e > 0 and 0 <= enc < p * q
	return pow(enc, inverse(e, (p - 1) * (q - 1) if p != q else p * (p - 1)), N)