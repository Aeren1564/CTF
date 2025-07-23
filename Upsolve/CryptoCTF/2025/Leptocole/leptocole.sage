#!/usr/bin/env sage

import sys
from flag import flag

def ranpermat(n, q):
	P = zero_matrix(n, n)
	I = list(range(n))
	shuffle(I)
	F = GF(q)
	for i in range(n):
		while True:
			r = F.random_element()
			if r != 0:
				P[i, I[i]] = r
				break
	return P

def die(*args):
	pr(*args)
	quit()
	
def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()
	
def sc():
	return sys.stdin.buffer.readline()

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::        Welcome to the Leotocole cryptography task!      :::.", border)
	pr(border, ".: Your mission is to find flag by analyzing the given oracle! :.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	global flag, q, n, k
	q, n, k = 127, 26, 14
	F = GF(q)
	G = random_matrix(F, k, n)
	Q = ranpermat(n, q)
	H = (G * Q).echelon_form()
	while True:
		pr(f"{border} Options: \n{border}\t[G]et the G and H! \n{border}\t[S]olve the Leotocole! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'g':
			pr(f'{G = }')
			pr(f'{H = }')
		elif ans == 's':
			pr(border, f'Please send the matrix U row by row: ')
			_U = []
			for _ in range(k):
				_r = sc().decode().strip()
				try:
					_r = [int(_) for _ in _r.split(',')]
					_U.append(_r)
				except:
					die(border, "Your input is not valid! Bye!!")
			pr(border, f'Now, please send the matrix P row by row: ')
			_P = []
			for _ in range(n):
				_r = sc().decode().strip()
				try:
					_r = [int(_) for _ in _r.split(',')]
					if _r.count(0) == n - 1:
						_P.append(_r)
				except:
					die(border, "Your input is not valid! Bye!!")
			try:
				_U = matrix(GF(q), _U)
				_P = matrix(GF(q), _P)
				if _U * G * _P == H and _U.is_invertible() and _P.is_invertible():
					_b = True
			except:
				die(border, "Something went wrong with your input :| Quitting!")
			if _b:
				die(border, f"Congrats, you got the flag: {flag}")
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()