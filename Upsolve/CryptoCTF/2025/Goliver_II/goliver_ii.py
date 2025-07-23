#!/usr/bin/env python3

from hashlib import sha256
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

def ADD(A, B):
	s = (B[1] - A[1]) * inverse(B[0] - A[0], p) % p
	x = (s**2 - A[0] - B[0]) % p
	y = (s * (A[0] - x) - A[1]) % p
	return (x, y)

def DOUBLE(A):
	s = ((3 * A[0] ** 2 + a) * inverse(2 * A[1], p)) % p
	x = (s**2 - 2 * A[0]) % p
	y = (s * (A[0] - x) - A[1]) % p
	return (x, y)

def MUL(A, d):
	_B = bin(d)[2:]
	_Q = A
	for i in range(1, len(_B)):
		_Q = DOUBLE(_Q)
		if _B[i] == "1":
			_Q = ADD(_Q, A)
	return _Q

def GENKEY():
	skey = getRandomRange(1, p)
	pubkey = MUL(G, skey)
	return (pubkey, skey)

def is_valid_k(k, used_k=set()):
	if k in used_k:
		return False
	used_k.add(k)
	return True

def _prepare(sign_id, msg):
	k = sign_id + int.from_bytes(msg, "big")
	if not is_valid_k(k):
		return None
	r, _ = MUL(G, k)
	hmsg = int.from_bytes(sha256(msg).digest(), "big")
	return k, r, hmsg

def sign(sign_id, msg):
	k, r, hmsg = _prepare(sign_id, msg)
	s = (inverse(k, n) * (hmsg + r * skey)) % n
	return s

def verify(sign_id, msg, s):
	_, r, hmsg = _prepare(sign_id, msg)
	u1 = (hmsg * inverse(s, n)) % n
	u2 = (r * inverse(s, n)) % n
	x1, _ = ADD(MUL(G, u1), MUL(pubkey, u2))
	return (x1 % n) == (r % n)

def main():
	border = "┃"
	pr("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(
		border,
		"Welcome! Our signature is half the size of traditional ECDSA, yet super",
		border,
	)
	pr(
		border,
		"secure with the BTC curve. Try the demo!                               ",
		border,
	)
	pr("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global p, a, b, G, n, pubkey, skey
	p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
	a, b = 0, 7
	n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
	x = 0x4F22E22228BD75086D77AE65174C000F132BFD4EF3E28BEF20AC476997D4444F
	y = 0x3456B224247A4F73BF187AC25864F8F694C078380E6BDDF51379AC33F18BD829
	G = (x, y)
	pubkey, skey = GENKEY()
	level, STEP, _b = 0, 3, False
	while True:
		pr(
			"| Options: \n|\t[S]ign flag \n|\t[V]erify sign \n|\t[G]et the flag \n|\t[P]ublic key \n|\t[Q]uit"
		)
		ans = sc().decode().strip().lower()
		if ans == "s":
			pr(border, f"Please provide sign_id:")
			sign_id = sc().decode()
			try:
				sign_id = int(sign_id)
				_b = sign_id > 0
			except:
				die(border, f"The input sign_id you provided is not valid!")
			if _b:
				s = sign(sign_id, msg = flag[:len(flag) >> 1])
				if s is None:
					die(border, f"Double use of the same sign_id is not possible!")
				pr(border, f"s = {s}")
				if level == STEP:
					die(border, f"You have only {STEP} rounds to check.")
				else:
					level += 1
			else:
				die(border, f"sign_id is a positive value! Bye!!")
		elif ans == "v":
			pr(border, "Please send the sign_id, message, and signature: ")
			inp = sc().decode()
			try:
				sign_id, msg, s = [int(_) for _ in inp.split(",")]
			except:
				die(border, f"The input you provided is not valid!")
			if verify(sign_id, msg, s):
				die(border, f"The signature is correct")
			else:
				die(border, f"The signature is incorrect")
		elif ans == "g":
			pr(border, "Please send the private key: ")
			_skey = sc().decode()
			try:
				_skey = int(_skey)
			except:
				die(border, "The private key is incorrect! Quitting...")
			if _skey == skey:
				die(border, f"Congrats, you got the flag: {flag}")
			else:
				die(border, f"The private key is incorrect! Quitting...")
		elif ans == "p":
			pr(border, f"pubkey = {pubkey}")
		elif ans == "q":
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == "__main__":
	main()