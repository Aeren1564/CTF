#!/usr/local/bin/python3
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes,bytes_to_long
import random
from secrets import token_bytes

flag = b'ictf{REDACTED}'


def helper(A,B,f,key):
	return (B,bytes([i ^ j for i,j in zip(A,f(B,key))]))
	
def func(A,key):
	c = AES.new(key,AES.MODE_ECB)
	out = c.encrypt(A)
	return out

seed = token_bytes(16)

def encrypt(message,keys):
	if len(message) > 32:
		raise Exception("no")
		
	A = message[:16]
	A += b'\x00' * (16 - len(A))
	B = message[16:]
	B += b'\x00' * (16 - len(B))
	
	
	for key in keys:
		(A,B) = helper(A,B,func,key)
	return A + B



def genkey():
	random.seed(seed)
	return long_to_bytes(random.randint(1 << 255, 1 << 256))
	


keys = [genkey() for _ in range(100)]


def main():

	while(True):
		try:
			option = int(input("1) print flag \n2) encrypt message\n>"))
			if (option == 1):
				print(bytes_to_long(encrypt(flag,keys)))
			elif (option == 2):
				print(bytes_to_long(encrypt(long_to_bytes(int(input('>'))),keys)))
			else:
				print('I don\'t understand that')
		except:
			print('dont try and break me >:C')
			exit(1)
if __name__ == '__main__':
	main()