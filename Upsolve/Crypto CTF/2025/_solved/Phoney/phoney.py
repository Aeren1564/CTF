#!/usr/bin/env python3

import sys, os
from Crypto.Util.number import *
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

def keygen(nbit):
	p, q, r = [getPrime(nbit + (nbit >> 3) * _) for _ in range(3)]
	return p, q, r

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, " Welcome to the Phoney crypto-system task, a nice cryptosystem   ", border)
	pr(border, " that's so good, it's theoretically unbreakable because it exists", border)
	pr(border, " only in the realm of imagination!! Try the get the long flag :-)", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag
	m = bytes_to_long(os.urandom(len(flag)) + flag + os.urandom(len(flag)))
	nbit = 512
	p, q, r = keygen(nbit)
	n, s, e = p * q * r, inverse(p, q * r) + p, 1234567891
	while True:
		pr(f"{border} Options: \n{border}\t[E]ncrypt the flag! \n{border}\t[P]ublic information \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'e':
			assert m < n
			c = pow(m, e, n)
			pr(f'{c = }')
		elif ans == 'p':
			pr(border, f'{n = }')
			pr(border, f'{s = }')
			pr(border, f'{q % p = }')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()