#!/usr/bin/env sage

from Crypto.Util.number import *
from time import *
from flag import flag

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc(): 
	return sys.stdin.buffer.readline()

def Ikkyu(nbit):
	p = getPrime(nbit)
	while True:
		a, b = [randint(1, p - 1) for _ in range(2)]
		E = EllipticCurve(GF(p), [a, b])
		G, H = [E.random_point() for _ in range(2)]
		try:
			I = E.lift_x(1)
		except:
			if legendre_symbol(b - a - 1, p) < 0:
				return p, E, G, H

def fongi(G, H, P):
	try:
		xG, xP, yP = G.xy()[0], P.xy()[0], P.xy()[1]
	except:
		xP = 1337
	return int(xP) * G + int(yP) * H + int(xG) * P

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Welcome to the Ikkyu-san challenge!! Your mission is to find the  ", border)
	pr(border, "flag with given information, have fun and good luck :)            ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit = 256
	pr(border, f'Generating parameters, please wait... ')
	p, E, G, H = Ikkyu(nbit)
	F = GF(p)
	while True:
		pr(f"{border} Options: \n{border}\t[E]ncrypted flag!\n{border}\t[R]andom point\n{border}\t[G]et Ikkyu-san point!\n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'g':
			pr(border, f"Please provide your desired point `P` on elliptic curve E like x, y: ")
			xy = sc().decode()
			try:
				x, y = [F(int(_)) for _ in xy.split(',')]
				P = E(x, y)
			except:
				pr(border, f"The input you provided is not valid!")
				P = E.random_point()
			pr(border, f'{fongi(G, H, P) = }')
		elif ans == 'r':
			pr(border, f'{E.random_point() = }')
		elif ans == 'e':
			m = bytes_to_long(flag)
			assert m < p
			pr(border, f'{m * G.xy()[0] * H.xy()[1] = }')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()