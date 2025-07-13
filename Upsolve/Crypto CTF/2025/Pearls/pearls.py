#!/usr/bin/env python3

import sys, time
from Crypto.Util.number import *
from secret import decrypt, FLAG

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
	p, q = [getPrime(nbit) for _ in '01']
	pkey = p * q
	skey = (p, q)
	return pkey, skey

def burnish(skey, l):
	nbit = skey[0].bit_length()
	IRE = [[getRandomRange(0, 2), getRandomNBitInteger(nbit + getRandomRange(-3, 3)), getRandomNBitInteger(int(nbit * 0.74))] for _ in range(l)]
	PLS = [skey[IRE[_][0]] * IRE[_][1] - IRE[_][2] for _ in range(l)]
	return PLS

def kouichi(r, l, n, e):
	nbit = n.bit_length()
	B = bin(r)[2:].zfill(nbit)[-(l + 1):]
	return pow(int(B, 2), e, n)

def encrypt(m, pubkey):
	n, e = pubkey, 1234567891
	r = getRandomRange(1, n)
	m1, m2 = (1 - r) * m % n, inverse(r, n) * m % n
	s = m1 * m2 % n
	u = (s + inverse(s, n)) * inverse(2, n) % n
	a = (inverse(s, n) - u) * inverse(m2, n) % n
	t = (u - a * m2) % n
	v = getRandomRange(1, n)
	l = n.bit_length() >> 1
	c0 = pow(v, e, n)
	c1 = (kouichi(v, l, n, e) + t * c0) % n
	c2 = (a + v**2) % n
	return c0, c1, c2

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".::               Welcome to the Pearls challenge!            ::. ", border)
	pr(border, " You should analyze this cryptosystem and break it to get the flag", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	nbit = 1024
	pkey, skey = keygen(nbit)
	m = bytes_to_long(FLAG)
	enc = encrypt(m, pkey)
	while True:
		pr("| Options: \n|\t[B]urnish the keys \n|\t[E]ncrypt the message \n|\t[P]ublic parameters \n|\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'e':
			pr(border, 'please send your message to encrypt: ')
			_m = sc().decode().strip()
			try:
				_m = int(_m)
			except:
				die(border, 'Your input is not correct! Bye!')
			_m = _m % pkey
			_enc = encrypt(_m, pkey)
			pr(border, f'enc = {_enc}')
		elif ans == 'p':
			pr(border, f'pkey = {pkey}')
			pr(border, f'encrypted_flag = {enc}')
		elif ans == 'b':
			pr(border, 'Please let me know how many times you want to burnish and burnish the key: ')
			l = sc().decode().strip()
			try:
				l = int(l) % 5
			except:
				die(border, 'Please be polite! Bye!!')
			PLS = burnish(skey, l)
			i = 0
			for pls in PLS:
				pr(border, f'PLS[{i}] = {PLS[i]}')
				i += 1
		elif ans == 'q': die(border, "Quitting...")
		else: die(border, "Bye...")

if __name__ == '__main__':
	main()