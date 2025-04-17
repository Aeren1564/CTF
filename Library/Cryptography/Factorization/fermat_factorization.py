# https://en.wikipedia.org/wiki/Fermat%27s_factorization_method
def fermat_factorization(n : int):
	from sage.all import is_prime, is_square
	if n % 2 == 0:
		return 2
	if is_prime(n):
		return n
	import gmpy2
	gmpy2.get_context().precision = 2048
	from math import ceil, floor
	a = int(ceil(gmpy2.sqrt(n)))
	b2 = a**2 - n
	while not is_square(b2):
		a += 1
		b2 = a**2 - n
	return a - int(ceil(gmpy2.sqrt(b2)))

"""
Tested on
- CyberSpaceCTF2024/crypto/ezcoppersmith
"""