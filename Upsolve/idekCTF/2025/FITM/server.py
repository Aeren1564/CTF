from Crypto.Util.number import *
import random
import os

class idek():

	def __init__(self, secret : bytes): 

		self.secret = secret
		self.p = None	

		self.poly = None 

	def set_p(self, p : int):

		if isPrime(p):
			self.p = p

	def gen_poly(self, deg : int):

		s = bytes_to_long(self.secret)
		l = s.bit_length()
		self.poly = [random.randint(0, 2**l) for _ in range(deg + 1)]
		index = random.randint(deg//4 + 1, 3*deg//4 - 1)
		self.poly[index] = s

	def get_share(self, point : int):

		if not self.p or not self.poly:
			return None

		return sum([coef * pow(point, i, self.p) for i, coef in enumerate(self.poly)]) % self.p

	def get_shares(self, points : list[int]):

		return [self.get_share(point) for point in points]

def banner():

	print("==============================================")
	print("=== Welcome to idek Secret Sharing Service ===")
	print("==============================================")
	print("")

def menu():

	print("")
	print("[1] Oracle")
	print("[2] Verify")
	print("[3] Exit")
		
	op = int(input(">>> "))
	return op

if __name__ == '__main__':

	S = idek(os.urandom(80))
	deg = 16
	seen = []

	banner()

	for _ in range(17):

		op = menu()
		if op == 1:
			p = int(input("What's Your Favorite Prime : "))
			assert p.bit_length() == 64 and isPrime(p) and p not in seen
			seen += [p]
			S.set_p(p)
			S.gen_poly(deg)
			L = list(map(int, input("> ").split(",")))
			assert len(L) <= 3*deg//4
			print(f"Here are your shares : {S.get_shares(L)}")
		elif op == 2:
			if S.secret.hex() == input("Guess the secret : "):
				with open("flag.txt", "rb") as f:
					print(f.read())
			else:
				print("Try harder.")
		elif op == 3:
			print("Bye!")
			break
		else:
			print("Unknown option.")
