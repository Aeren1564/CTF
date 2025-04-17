def RSA_decrypt(enc : int, p : int, q : int, e : int):
	from Crypto.Util.number import inverse, isPrime
	assert isPrime(p)
	assert isPrime(q)
	assert e > 0
	assert 0 <= enc < p * q
	emod = (p - 1) * (q - 1) if p != q else p * (p - 1)
	from sage.all import gcd
	if gcd(emod, e) == 1:
		return [pow(enc, inverse(e, emod), p * q)]
	else:
		from sage.all import pari, Zmod
		pari.addprimes(p)
		base = Zmod(p * q)(enc).nth_root(e)
		root = Zmod(p * q)(1).nth_root(e)
		return [int(base * root**i) for i in range(e)]
