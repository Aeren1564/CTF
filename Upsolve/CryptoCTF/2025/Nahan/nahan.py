#!/usr/bin/env python3

import sys
from Crypto.Util.number import *
from random import *
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

def next_prime(n):
	while True:
		if isPrime(n): return n
		else: n += 1

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::     Welcome to the Nahan Maskara cryptography task!      ::.", border)
	pr(border, ".: Your mission is to find flag by analysing the Nahan Maskara :.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	secret = getPrime(len(flag) << 3)
	l, c, step = secret.bit_length(), 0, secret.bit_length() >> 1
	while True:
		pr(f"{border} Options: \n{border}\t[G]et Nahan value! \n{border}\t[S]end secret! \n{border}\t[Q]uit")
		R, _b = [], False
		ans = sc().decode().strip().lower()
		if ans == 'g':
			pr(border, 'Now please provide two integers s, t: ')
			inp = sc().decode().strip()
			try:
				s, t = [int(_) for _ in inp.split(',')]
				if all(3 * l > 6 * _.bit_length() > 2 * l for _ in (s, t)):
					_b = True
			except:
				die(border, f"The input you provided is not valid!")
			if _b:
				r = next_prime(s * t ^ 2 ** l)
				if r in R:
					die(border, 'You cannot use repeated integers! Bye!!')
				else:
					R.append(r)
				u = list(bin(secret ^ r)[2:])
				shuffle(u)
				pr(border, f'n = {r * int("".join(u), 2)}')
				if c >= step:
					die(border, f'You can get Nahan value at most {step} times! Bye!!')
				c += 1
			else:
				die(border, f"Your input does not meet the requirements!!!")
		elif ans == 's':
			pr(border, "Please send secret: ")
			_secret = sc().decode()
			try:
				_secret = int(_secret)
			except:
				die(border, "The secret is incorrect! Quitting...")
			if _secret == secret:
				die(border, f"Congrats, you got the flag: {flag}")
			else:
				die(border, "The secret is incorrect! Quitting...")
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()