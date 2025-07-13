#!/usr/bin/env sage

from Crypto.Util.number import *
import time, sys
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

def gen_CP(nbit):
	R.<x> = PolynomialRing(GF(2))
	while True:
		c = ''.join([hex(randint(0, 15))[2:] for _ in range(nbit >> 2)])
		G = R(Integer(int(c, 16)).bits()[::-1]) + x ^ nbit
		if G.is_irreducible():
			return int(c, 16)

def recheck(msg, v):
	for m in msg:
		v = v ^^ m
		v = (v >> 8) ^^ CT[v & 0xFF] 
	return v & 0xFFFFFFFFFFFFFFFF 

def verify(v, t):
	return recheck(long_to_bytes(skey ^^ t), v) == v

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".::              Welcome to the Asemoon challenge!            ::. ", border)
	pr(border, " You should analyze this login oracle and break it to get the flag", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global nbit, skey, CT
	nbit = 64
	skey = getRandomNBitInteger(nbit)
	CP, CT = gen_CP(nbit), []
	for _ in range(256):
		cb = _
		for _ in range(8):
			if cb & 1:
				cb = (cb >> 1) ^^ CP
			else:
				cb >>= 1
		CT.append(cb & 0xFFFFFFFFFFFFFFFF)
	while True:
		pr(f"{border} Options: \n{border}\t[L]ogin \n{border}\t[P]ublic information! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'l':
			pr(border, 'Please send your hex token here:')
			token = sc().decode().strip()
			try:
				token = int(token, 16)
			except:
				die(border, "Your token is invalid! Bye!!")
			if 0 <= token < 2**nbit:
				t = int(time.time())
				t -= t % 10
				if verify(token, t):
					die(border, f"Congrats, you got the flag: {flag}")
			die(border, "Your token is wrong!")
		elif ans == 'p':
			t = int(time.time())
			t -= t % 10
			pub_1 = recheck(b"CCTF", recheck(long_to_bytes(skey ^^ t), 0))
			while True:
				pub_2 = getPrime(nbit)
				if pub_2 > CP:
					break
			pub_3 = pow(5, CP, pub_2)
			pr(border, f'The first public information is:  {pub_1}')
			pr(border, f'The second public information is: {pub_2}')
			pr(border, f'The third public information is:  {pub_3}')
		elif ans == 'q': die(border, "Quitting...")
		else: die(border, "Bye...")

if __name__ == '__main__':
	main()