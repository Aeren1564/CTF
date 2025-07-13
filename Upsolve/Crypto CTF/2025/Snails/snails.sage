#!/usr/bin/env sage

import sys
from Crypto.Util.number import *
from hashlib import sha512
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

def sign(msg, skey):
	h = bytes_to_long(sha512(msg).digest())
	k = getRandomNBitInteger(h.bit_length())
	P = k * G
	r = int(P.xy()[0]) % n
	s = pow(k, -1, n) * (h + r * skey) % n
	return (r, s)

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, " Hey! To solve the Snails cryptography challenges one often needs", border)
	pr(border, " to perform meticulous bit by bit analysis to uncover loopholes  ", border)
	pr(border, " and ultimately extract the high value flag! Good luck ;) 🐌🐌🐌 ", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag, G, n
	skey = bytes_to_long(flag)
	p = 0x013835f64744f5f06c88c8d7ebfb55e127d790e5a7a58b7172f033db4afad4aca1ae1cdb891338cf963b30ff08d6af71327770d00c472c52290a60fb43f1d070025b
	a = 0x0109ec0177a5a57e7b7890993e11ba1bc7ba63c1f2afd904a1df35d1fda7363ea8e83f3291e25b69dac26d046dc5ba9a42ff74cd7e52c9df5dbe8d4d02755d26b111
	b = 0x0037c84047a6cc14e36d180f9b688fe9959cb63f4ac37b22eb24559e83cfc658ff0ab753540b8ab8d85a62dd67aa92f79dec20d28e453d4663ef2882c7b031ddc0b9
	n = 0x013835f64744f5f06c88c8d7ebfb55e127d790e5a7a58b7172f033db4afad4aca1aad8763fe2401b5189d1c449547a6b5295586ce30c94852845d468d52445548739
	x = 0x00339495fdbeba9a9f695d6e93effeb937609ce2e628958cd59ba307eb3a43c4c3a54b9b951cd593c876df93a9b0ed7d64df641af94668cb594b6a636ae386e1ac1b
	y = 0x00038389f29ad8c87e79a8b854e78310b72febb6b1840e360b0a43733933529ee6a04f6d7ea0d91104eb83d1162d55c410eca1c7b45829925fb2a9bf9c1232c32972
	E = EllipticCurve(GF(p), [a, b])
	G = E(x, y)
	m = '✔✔✔ My signature is the priority'.encode()
	while True:
		pr(f"{border} Options: \n{border}\t[S]ign message! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 's':
			pr(border, f'Please send your message: ')
			msg = sc().strip()
			if m in msg and len(msg) == 40:
				r, s = sign(msg, skey)
				pr(border, f'{r = }')
				pr(border, f'{s = }')
			else:
				die(border, 'Not valid message! Bye!!')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()