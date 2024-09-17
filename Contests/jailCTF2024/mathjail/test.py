from CTF_Library import *

def ptest(n):
	return n == 2 or n != 341 and pow(2, n - 1, n) == 1

def check():
	for x in range(1, 500):
		if is_prime(x) != ptest(x):
			print(f"Failed on {x = }")
			return False
	return True

print(check())
