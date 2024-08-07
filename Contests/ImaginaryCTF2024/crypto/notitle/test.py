from sage.all import *

proof.all(False)

p = 0x7AADA0BA1C05D63803BA6BCE66CB6BC091C7ADA62B5CB5BC9F924B528FC113971D4BC54C7FAF3C146ADEB0548BFB9258DFF316741266B802DD7A2F46F77593BAD983E6DF394C1519E8DB0130289FA5A9C628E3ABCE58C63B3379DB7088AAC7A40B63776959774B1B57B8FD316C650AE3C012A91EE653477443446050438A99E79B89B69745BD1918EECB08A0C9D45EF3C61639137F24D979FF380D65C7ABD08785F1AF99729A62F3690747AEC4CCBDA99BAE6E990A0FEFF6F1AB9ABEAFE7FB5BDDB8471C607DEC16198A2AE7776C56B5B6CA24B4C0A2441A047A18EB23302B46CC49ADFF6188FC97C886D5BF67B4B0EFF56762C4E48AAD3F02E7CFE8AA157FB1789B1
F = GF(p)

R, (X, ) = PolynomialRing(ZZ, "X").objgens()

def magic_op(x, n: int):
	r0, r1 = 1, x
	for b in f"{n:b}":
		if b == "0":
			r1 = 2 * r0 * r1 - x
			r0 = 2 * r0**2 - 1
		else:
			r0 = 2 * r0 * r1 - x
			r1 = 2 * r1**2 - 1
	return r0

polys = []
for n in range(20):
	poly = magic_op(X, n)
	print(f"{n = }")
	print(poly)
	if n >= 2:
		print(2 * X * polys[-1] - polys[-2])
	print()
	polys.append(poly)

pi = F(314159)
e = F(271828)
pi_sqrt = (pi * pi - 1).sqrt(extend = True)
e_sqrt = (e * e - 1).sqrt(extend = True)

for i in range(100):
	assert magic_op(pi, i) == ((pi + pi_sqrt)**i + (pi - pi_sqrt)**i) / 2
	assert magic_op(e, i) == ((e + e_sqrt)**i + (e - e_sqrt)**i) / 2

rem = p - 1
pfactors = [2, 2, 2, 2, 3, 3, 5, 5, 7, 11, 19, 29, 31, 37, 41, 61, 331, 3433, 22381, 59011, 903151, 407716853, 1344521821, 1440133381, 1827022597, 1972851313, 9985849697, 29986907677, 1043610062213431, 6247344214605031, 1853188607292839129, 721894921019602741141]
for x in pfactors:
	assert x in Primes()
	assert rem % x == 0
	rem //= x

print(len(bin(p)))


while rem not in Primes():
	x = trial_division(Integer(rem))
	print(f"New factor {x}")
	assert x in Primes()
	assert rem % x == 0
	rem //= x

print(f"{pfactors = }")