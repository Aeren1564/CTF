#!/usr/bin/env python3

from random import *
from flag import flag
import sys
from os import urandom

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

class Shooti:
	def __init__(self, key, vec):
		self.SETTIMER = 160
		self.NEXT = [0 for _ in range(80)]
		self.BEST = [0 for _ in range(80)]
		self.SBOX = [
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0,
				0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1,
				0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0,
				1, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 1,
				0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0,
				1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1,
				0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0
		]
		self.LOGIC = [1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1]
		self.klen, self.vlen = 80, 64
		
		key = [key[_:_ + 2] for _ in range(0, len(key), 2)]
		self.key = [int(_, 16) for _ in key]
		vec = [vec[_:_ + 2] for _ in range(0, len(vec), 2)]
		self.vec = [int(_, 16) for _ in vec]

		for i in range(self.vlen // 8):
			for j in range(8):
				self.NEXT[i * 8 + j] = (self.key[i] >> j) & 1
				self.BEST[i * 8 + j] = self.NEXT[i * 8 + j]

		for i in range(self.vlen // 8, self.klen // 8):
			for j in range(8):
				self.NEXT[i * 8 + j] = (self.key[i] >> j) & 1
				self.BEST[i * 8 + j] = 1
		
		for _ in range(self.SETTIMER):
			RESB = self.BITSEQ()
			self.BEST[79] ^= RESB
			self.NEXT[79] ^= RESB
	def N(self, c):
		return self.NEXT[80 - c]
	def B(self, c):
		return self.BEST[80 - c]

	def BITSEQ(self):
		B0, B1, B2, B3 = self.BEST[3], self.BEST[25], self.BEST[46], self.BEST[64]
		N0 = self.NEXT[63]
		RESB = self.N(79) ^ self.N(78) ^ self.N(76) ^ self.N(70) ^ self.N(49) ^ self.N(37) ^ self.N(24) ^ self.LOGIC[(N0 << 4) | (B3 << 3) | (B2 << 2) | (B1 << 1) | B0]
		NBit = self.B(80) ^ self.N(18) ^ self.N(66) ^ self.N(80) ^ self.SBOX[sum(self.N(i) << (9 - j) for j, i in enumerate([17, 20, 28, 35, 43, 47, 52, 59, 65, 71]))]	
		LBit = self.B(18) ^ self.B(29) ^ self.B(42) ^ self.B(57) ^ self.B(67) ^ self.B(80)
		for i in range(1, self.klen):
			self.NEXT[i - 1] = self.NEXT[i]
			self.BEST[i - 1] = self.BEST[i]
		self.NEXT[self.klen - 1] = NBit
		self.BEST[self.klen - 1] = LBit		
		return RESB
	def BYTESEQ(self):
		while True:
			BITSEQ = 0
			for j in range(8):
				RESB = self.BITSEQ()
				RESB <<= j
				BITSEQ = BITSEQ | RESB
			yield BITSEQ

	def encrypt(self, MSG):
		enc = [M ^ B for M, B in zip(MSG, self.BYTESEQ())]
		return enc
	
class MultiShooti:
	def __init__(self, keys, vec):
		self._encs = [Shooti(key, vec) for key in keys]
	def encrypt(self, MSG):
		res = MSG
		for enc in self._encs:
			res = enc.encrypt(res)
		return res

def main():
	global flag
	border = "┃"
	pr("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(
		border,
		"Welcome, challenger! We've crafted an ultra-secure encryption system",
		border,
	)
	pr(
		border,
		"with multiple layers of encryption. But... we kinda forgot the keys!",
		border,
	)
	pr(
		border,
		"Can you help us recover them? Good luck!                            ",
		border,
	)
	pr("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	
	p = list(map(ord, "give me the flag!"))
	keys = [urandom(10).hex() for _ in range(8)]
	vec = urandom(8).hex()
	c = MultiShooti(keys, vec).encrypt(p)
	while True:
		pr(
			border, f"Options: \n{border}\t[D]ecrypt \n{border}\t[C]ipher \n{border}\t[Q]uit"
		)
		ans = sc().decode().strip().lower()
		if ans == "d":
			pr(border, "Please send keys:")
			_keys = sc().decode()
			try:
				_keys = list(map(str.strip,_keys.split(",")))
				_b = all(int(_, 16).bit_length() == 80 for _ in _keys)
			except:
				die(border, "Invalid input! Quitting...")
			if _b:
				tmp = MultiShooti(_keys, vec).encrypt(c)
				pr(border, f"plaintext = {tmp}")
				if tmp == p:
					die(border, f"Congrats, you got the flag: {flag}")
			else:
				die(border, "Invalid input! Quitting...")
		elif ans == "c":
			pr(border, f"challenge cipher = {c}")
		elif ans == "q":
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == "__main__":
	main()