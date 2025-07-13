#!/usr/bin/env sage

import sys
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

def randroad(B):
	return vector(ZZ,[randint(-B, B) for _ in range(n)])

def roadband():
	return randroad(B * (D + 1))

def silky(key):
	while True:
		R = roadband()
		_R = R - key
		if min(_R) >= - B * D and max(_R) <= B * D:
			return R

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::      Welcome to the Silky cryptography oracle task!     :::.", border)
	pr(border, "Your mission is to find flag by analyzing this weird oracle! :-) ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag, B, n, D, t
	B, n = 5, 19
	D, t = 110, 128
	l = int(4 * D * B / t)
	c, key = 0, randroad(B)
	while True:
		c += 1
		if c >= 12:
			die(border, "My brain is fried, quitting...")
		pr(f"{border} Options: \n{border}\t[G]et flag! \n{border}\t[M]ake Silky! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'm':
			R = [silky(key) for _ in range(int(l * t // 2))]
			for i in range(len(R) // 16):
				pr(border, f"{str(R[16 * i:16 * (i + 1)]).replace(',', '')}")
		elif ans == 'g':
			pr(border, f'Please submit the secret key: ')
			inp = sc().decode().strip()
			try:
				_key = vector(ZZ, [int(_) for _ in inp.split(',')])
			except:
				die(border, f'The input you provided is not valid! Bye!!')
			if _key == key:
				die(border, f'Congrats! You got the flag: {flag}')
			else:
				die(border, f'Your key is incorrect!')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()