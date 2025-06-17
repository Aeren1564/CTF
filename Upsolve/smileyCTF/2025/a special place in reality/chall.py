#!/usr/local/bin/python
from Crypto.Util.number import *
import math

FLAG = open('flag.txt').read()

while True:
	if input("Yes? ") == "yes":
		try:
			x = int(input("Length: "))
			if x <= len(FLAG) * 40:
				p = getPrime(x)
			elif x <= 10000: # no dos pls
				p = 256
			n = p*p

			flag = FLAG + "a" * (1 + math.ceil(x/8))
			flag = bytes_to_long(flag.encode())
			flag = flag - flag % p

			c = pow(flag, 65537, n)

			print("p multiple length:", len(bin(flag//p)) - 2)
			print("p multiple 1 bits:", bin(flag//p).count("1"))
			print(c, 65537, n)
			
		except:
			print("invalid input")
	else:
		print("exiting...")
		exit(0)