#!/usr/bin/env python3

from quantcrypt.kem import MLKEM_1024
import sys, os, string
from random import randint
import hashlib
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

def rand_str(l):
	charset = string.printable[:63] + '_'
	return ''.join([charset[randint(0, 63)] for _ in range(l)]).encode()

def pow():
	head = rand_str(15)
	tail = rand_str(4)
	h = hashlib.sha3_256(head + tail).hexdigest()
	return head, h

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::       Welcome to the Mechanic II cryptography task!      ::.", border)
	pr(border, "Your mission is to find flag by analyzing this amazing Oracle! :)", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	head, h = pow()
	pr(border, f'Please pass the proof of work first: {head, h}')
	_tail = sc().strip()
	if hashlib.sha3_256(head + _tail).hexdigest() == h:
		_b = True
	else:
		die(border, 'Your should pass the POW! Bye!!')
	kem = MLKEM_1024()
	c, n = 0, 1337
	KEY_PAIR = [kem.keygen() for _ in range(n)]
	SKEYS = [KEY_PAIR[_][1] for _ in range(n)]
	#r = randint(0, n - 1)
	r = 0
	cipher, shasec = kem.encaps(KEY_PAIR[r][0])
	secret = hashlib.sha3_256(shasec + hashlib.sha3_256(shasec + str(r).encode()).digest()).hexdigest()
	while _b:
		if c > 3 * n:
			die(border, 'The server is need to rest :/')
		pr(f"{border} Options: \n{border}\t[D]ecrypt cipher \n{border}\t[R]andomize a secret key! \n{border}\t[S]ubmit the secret \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		c += 1
		if ans == 'd':
			pr(border, 'Please select an ID: ')
			_id = sc().decode().strip()
			try:
				_id = int(_id)
				_shasec = kem.decaps(SKEYS[_id], cipher)
			except:
				die(border, 'Your input ID is invalid! Bye!!')
			pr(border, f'{_shasec = }')
		elif ans == 'r':
			pr(border, 'Please select an ID: ')
			_id = sc().decode().strip()
			try:
				_id = int(_id)
				_skey = SKEYS[_id][:-32] + os.urandom(32)
			except:
				die(border, 'Your input ID is invalid! Bye!!')
			SKEYS.append(_skey)
		elif ans == 's':
			pr(border, 'Please send the secret: ')
			_secret = sc().decode().strip()
			if _secret == secret:
				die(border, f'Congrats, you got the flag: {flag}')
			else:
				die(border, 'Your secret is incorrect! Bye!!')
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()