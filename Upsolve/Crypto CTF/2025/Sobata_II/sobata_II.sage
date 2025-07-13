#!/usr/bin/env sage

import sys, re
from Crypto.Util.number import *
from flag import FLAG

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc(): 
	return sys.stdin.buffer.readline()

def sanitize_string(inp):
	pattern = r'[^0-9g*+,]|[a-fh-zA-FH-Z]'
	return re.sub(pattern, '', inp)

def gen_params(nbit):
	while True:
		p = getPrime(nbit)
		R.<x> = PolynomialRing(GF(p))
		f = x^2 + 13 * x + 37
		f = R(f)
		if f.is_irreducible():
			F.<g> = GF(p^2, modulus = f)
			while True:
				a, b = [__ ** (__.multiplicative_order() // (3 - _)) for _, __ in enumerate(F.random_element() for _ in ':)')]
				if a.multiplicative_order() - 3 == b.multiplicative_order() - 2 == 0:
					c, d = [randint(1, p) for _ in ':)']
					E = EllipticCurve(F, [0, d])
					return (p, F, E, a, b, c)

def walk(P, parameters):
	p, F, E, a, b, c = parameters
	x, y = P.xy()
	Q = (a * x, b * y)
	assert Q in E
	return int(c) * E(Q)

def jump(P, n, parameters):
	_parameters = list(parameters)
	_parameters[-1] = pow(int(_parameters[-1]), n, _parameters[1].order())
	return walk(P, _parameters)

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".::             Welcome to the Sobata II challenge!           ::. ", border)
	pr(border, " You should analyze this weird oracle and break it to get the flag", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit = 196
	parameters = gen_params(nbit)
	p, F, E = parameters[0], parameters[1], parameters[2]
	g = F.gen()
	m = bytes_to_long(FLAG)
	assert m < p
	while True:
		try:
			P = E.lift_x(m + 1404 * g)
			break
		except:
			m += 1
	while True:
		pr("| Options: \n|\t[E]ncrypted FLAG \n|\t[W]alking with P \n|\t[J]umping over P \n|\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'e':
			_P = walk(P, parameters)
			pr(border, f'The encrypted flag is: {_P.xy()}')
		elif ans == 'w':
			pr(border, 'Please send your desired point over E: ')
			Q = sc().decode().strip()
			Q = sanitize_string(Q).split(',')
			try:
				allowed_vars = {'g': g}
				Q = [eval(_, {'__builtins__': None}, allowed_vars) for _ in Q]
			except:
				die(border, 'Your input is not valid!!')
			if Q in E:
				pr(border, f'The result of the walk is: {walk(E(Q), parameters).xy()}')
			else:
				die(border, 'Your point is not on the curve E! Bye!!')
		elif ans == 'j':
			pr(border, 'Send your desired point over E: ')
			Q = sc().decode().strip()
			Q = sanitize_string(Q).split(',')
			pr(border, 'Let me know how many times you would like to jump over the given point: ')
			n = sc().decode().strip()		
			try:
				allowed_vars = {'g': g}
				Q = [eval(_, {'__builtins__': None}, allowed_vars) for _ in Q]
				n = int(n)
			except:
				die(border, 'Your input is not valid!!')
			if Q in E:
				pr(border, f'The result of the jump is: {jump(E(Q), n, parameters).xy()}')
			else:
				die(border, 'Your point is not on the curve E! Bye!!')
		elif ans == 'q': die(border, "Quitting...")
		else: die(border, "Bye...")

if __name__ == '__main__':
	main()