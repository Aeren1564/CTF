#!/usr/bin/env sage

import sys, string
from Crypto.Util.number import *
from hashlib import sha1
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

def h(a):
	if a == 0:
		return 0
	else:
		g = F.gen()
		for _ in range(1, 256):
			if g ** _ == a:
				return _

def H(M):
	assert M.nrows() == M.ncols()
	k, _H = M.nrows(), []
	for i in range(k):
		for j in range(k):
			_h = h(M[i, j])
			_H.append(bin(_h)[2:].zfill(8))
	return ''.join(_H)

def Hinv(m, k):
	B = bin(m)[2:].zfill(8 * k**2)
	g = F.gen()
	_H = [int(B[8*i:8*i + 8], 2) for i in range(k**2)]
	_M = [0 if _h == 0 else g ** _h for _h in _H]
	M = Matrix(F, [[a for a in _M[k*i:k*i + k]] for i in range(k)])
	return M

def M2i(M):
	_H = H(M)
	return int(_H, 2)

def random_oracle(msg):
	_h = sha1(msg).digest()
	return bytes_to_long(_h)

def makey(k):
	while True:
		g = random_matrix(F, k)
		if g.is_invertible():
			ng = 1 << 192 # g.order()
			break
	r, a = [randint(2, ng - 2) for _ in '01']
	gg = g ** r
	pkey, skey = (g, gg ** a), r
	return(pkey, skey)

def sign(pkey, skey, msg):
	g, ga = pkey
	ng = 1 << 192 # g.order()
	_h = random_oracle(msg)
	assert _h <= ng
	_g = g ** skey
	n = randint(2, ng - 2)
	s, t = ga * (_g.inverse()) ** (n * _h), _g ** n
	return (s, t)

def verify(sgn, pkey, msg):
	_, ga = pkey
	s, t = sgn
	_h = random_oracle(msg)
	return s * t ** _h == ga

def main():
	border = "┃"
	pr("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "Hi all, now it's time to sign a given message in a strange signature", border)
	pr(border, "schema. You will receive the flag if you are able to sign a message.", border)
	pr("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	global F, k
	F = GF(256)
	k = 10
	pkey, skey = makey(k)

	msg = ''.join([string.printable[randint(0, 85)] for _ in range(40)]).encode()

	while True:
		pr("| Options: \n|\t[G]et the flag \n|\t[P]ublic Key \n|\t[S]ign a message \n|\t[V]erify signature \n|\t[Q]uit")
		ans = sc().decode().lower().strip()
		if ans == 'g':
			pr(border, 'You should send the valid signature for my given message!')
			pr(border, f'Message = {msg}')
			pr(border, 'Send the signature of the above message: ')
			_sgn = sc().split(b',')
			try:
				_s, _t = [int(_) for _ in _sgn]
				sgn = (Hinv(_s, k), Hinv(_t, k))
				if verify(sgn, pkey, msg) and str(_s).startswith('13') and str(_t).startswith('37'):
					pr(border, f'Congratulation! You got the flag!')
					die(border, f'flag = {flag}')
				else:
					pr(border, 'Your signature is not correct!')
			except:
				die(border, 'Exiting...')
		elif ans == 's':
			pr(border, 'Send your message to sign: ')
			_msg = sc().strip()
			if len(_msg) >= 10:
				die(border, 'Sorry, I sign only short messages! :/')
			_s, _t = sign(pkey, skey, _msg)
			pr(border, f's = {M2i(_s)}')
			pr(border, f't = {M2i(_t)}')
		elif ans == 'v':
			pr(border, 'Send your signature to verify: ')
			_sgn = sc().split(b',')
			try:
				_s, _t = [int(_) for _ in _sgn]
				_sgn = (Hinv(_s, k), Hinv(_t, k))
				pr(border, 'Send your message: ')
				_msg = sc().strip()
				if verify(_sgn, pkey, _msg):
					pr(border, 'Your message successfully verified :)')
				else:
					pr(border, 'Verification failed :(')
			except:
				pr(border, 'Try to send valid signature!')
				continue
		elif ans == 'p':
			_g, _ga = pkey
			pr(border, f'g  = {M2i(_g)}')
			pr(border, f'ga = {M2i(_ga)}')
		elif ans == 'q':
			die(border, 'Quitting...')
		else:
			die(border, 'You should select valid choice!')

if __name__ == '__main__':
	main()