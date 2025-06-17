import random
import math
from Crypto.Util.number import *
from Crypto.Cipher import AES

flag = open("flag.txt", "rb").read()

class fLCG():
	def __init__(self, l):
		self.m = getPrime(l)
		self.a = random.randint(1, self.m-1)
		self.c = random.randint(1, self.m-1)

		self.state = float(random.randint(1, self.m))

	def __iter__(self):
		return self
	
	def __next__(self):
		self.state = (self.a * self.state + self.c) % self.m
		return int(self.state)
	
x = iter(fLCG(512))

def get_number():
	return next(x) % (2**64 - 59)
 
def get_blocks(c):
	return b''.join(get_number().to_bytes(8, 'big') for _ in range(c))

key = get_blocks(2)
cipher = AES.new(key, AES.MODE_ECB)

flag_enc = cipher.encrypt((flag + b' ' * 15)[:1-(len(flag)%16)])

open("out.txt", "w").write(f"the flag is {get_blocks(4).hex()}\noops... my finger slipped\nthe flag is actually {flag_enc.hex()}")