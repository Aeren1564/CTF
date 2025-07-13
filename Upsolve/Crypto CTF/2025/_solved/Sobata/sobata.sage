#!/usr/bin/env sage

import sys
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

def gen_params(nbit):
	while True:
		p = getPrime(nbit)
		if p % 6 == 1:
			F = GF(p)
			R = [F.random_element() for _ in '01']
			a, b = [R[_] ** ((p - 1) // (3 - _)) for _ in [0, 1]]
			if a != 1 and b != 1:
				c, d = [F.random_element() for _ in '01']
				E = EllipticCurve(GF(p), [0, d])
				return (p, E, a, b, c)

def walk(P, parameters):
	p, E, a, b, c = parameters
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
	pr(border, ".::               Welcome to the Sobata challenge!            ::. ", border)
	pr(border, " You should analyze this weird oracle and break it to get the flag", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit = 512
	parameters = gen_params(nbit)
	E = parameters[1]
	m = bytes_to_long(FLAG)
	assert m < parameters[0]
	while True:
		try:
			P = E.lift_x(m)
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
			Q = sc().decode().strip().split(',')
			try:
				Q = [int(_) for _ in Q]
			except:
				die(border, 'Your input is not valid!!')
			if Q in E:
				pr(border, f'The result of the walk is: {walk(E(Q), parameters).xy()}')
			else:
				die(border, 'Your point is not on the curve E! Bye!!')
		elif ans == 'j':
			pr(border, 'Send your desired point over E: ')
			Q = sc().decode().strip().split(',')
			pr(border, 'Let me know how many times you would like to jump over the given point: ')
			n = sc().decode().strip()		
			try:
				Q = [int(_) for _ in Q]
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