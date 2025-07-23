#!/usr/bin/env sage

from Crypto.Util.number import *
from flag import flag

nbit, ebit, xbit = 512, 72, 313
Q = 2 ** (nbit - xbit)

def keygen(nbit):
	while True:
		p, q = [getPrime(nbit) for _ in ':)']
		n, phi = p * q, (p - 1) * (q - 1)
		if n.bit_length() == 2 * nbit:
			e = getPrime(ebit)
			if GCD(e, phi) > 1:
				continue
			u, v = [inverse(e, _ - 1) for _ in [p, q]] 
			k = (e * u - 1) // (p - 1)
			l = (e * v - 1) // (q - 1)
			if GCD(2 * e, k) == 1:
				break
	U, V = u % Q, v % Q
	return n, e, U, V

n, e, U, V = keygen(nbit)
m = bytes_to_long(flag)
assert m < n
c = pow(m, e, n)

print(f'{e = }')
print(f'{n = }')
print(f'{U = }')
print(f'{V = }')
print(f'{c = }')