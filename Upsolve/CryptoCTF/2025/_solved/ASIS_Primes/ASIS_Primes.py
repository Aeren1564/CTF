#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from random import randint
import string
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

def is_valid(msg):
	msg, charset = msg.decode(), string.printable[:63] + '_{-}'
	return all(_ in charset for _ in msg)

def rand_str(l):
	charset = string.printable[:63] + '_'
	return ''.join([charset[randint(0, 63)] for _ in range(l)])

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::       Welcome to the ASIS Primes cryptography task!      ::.", border)
	pr(border, ".: Your mission is to find flag by analyzing the crypto-system :.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag
	nbit = 512
	p, q = [getPrime(nbit) for _ in range(2)]
	e = 65537
	while True:
		pr(f"{border} Options: \n{border}\t[E]ncrypted the flag! \n{border}\t[S]ubmit primes! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'e':
			m = bytes_to_long(flag)
			c = pow(m, e ^ 1, p * q)
			pr(f'{c = }')
		elif ans == 's':
			pinit = f'CCTF{{7H!S_iZ_th3_f1RSt_pRim3__P_f0R_oUr_{nbit}-bit_m0DulU5_{rand_str(randint(5, 40))}'.encode()
			qinit = f'CCTF{{7H!S_iZ_th3_s3c0Nd_pRim3_Q_f0R_oUr_{nbit}-bit_m0DulU5_{rand_str(randint(5, 40))}'.encode()
			pr(border, f'the condition for the first  prime is: {pinit}')
			pr(border, f'the condition for the second prime is: {qinit}')
			pr(border, f'Please submit the primes p, q: ')
			inp = sc().decode().strip()
			try:
				_p, _q = [int(_) for _ in inp.split(',')]
				_pbytes, _qbytes = [long_to_bytes(_) for _ in (_p, _q)]
				if (
					isPrime(_p) and isPrime(_q) 
					and _pbytes.startswith(pinit) and _qbytes.startswith(qinit) 
					and _pbytes.endswith(b'}') and _qbytes.endswith(b'}') 
					and is_valid(_pbytes) and is_valid(_qbytes)
					and (9 * _p * _q).bit_length() == 2 * nbit
					):
						p, q = _p, _q
			except:
				pr(border, f'The input you provided is not valid! Try again!!')
				nbit += 1
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()