#!/usr/bin/env sage


from Crypto.Util.number import *
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

def gen_curve(p, l, n):
	while True:
		a = randint(1, p - 1)
		b = randint(1, p - 1)
		E = EllipticCurve(Zmod(p ^ l), [a, b])
		try:
			PTS = [E.lift_x(_ + 1) for _ in range(n)]
			return PTS
		except:
			continue

def main():
	border = "┃"
	pr(        "┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, ".:::          Welcome to the Hoshi cryptography task!         :::.", border)
	pr(border, ".:: Your mission is to find flag by analysing the Hoshi system ::.", border)
	pr(        "┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")

	nbit = 256
	l, p, n = 12, getPrime(nbit), 5
	PTS = gen_curve(p, l, n)
	SCV = [randint(1, p ^ (l - 1)) for _ in range(n)]
	EPT = [SCV[_] * PTS[_] for _ in range(n)]
	ORD = [
		(1, "first"), 
		(2, "second"),
		(3, "third"),
		(4, "forth"),
		(5, "fifth")
		]
	while True:
		pr(f"{border} Options: \n{border}\t[B]ase Points \n{border}\t[E]ncrypted Points \n{border}\t[S]olve the Hoshi! \n{border}\t[Q]uit")
		ans = sc().decode().strip().lower()
		if ans == 'b':
			for _ in range(n):
				pr(border, f'BPT_{_ + 1} = {PTS[_][1]}')
		elif ans == 'e':
			for _ in range(n):
				pr(border, f'EPT_{_ + 1} = {EPT[_][0]}')	
		elif ans == 's':
			for _ in range(n):
				_b = False
				pr(border, f"Please provide the {ORD[_][1]} integer:")
				inp = sc().decode()
				try:
					s = int(inp)
					if s * PTS[_] == EPT[_]:
						_b = True
				except:
					die(border, f"The input you provided is not valid!")
				if _b:
					if _ == n - 1:
						die(border, f'Congratulations! You got the flag: {flag}')
					else:
						pr(border, f'Great job, now try the {ORD[_][1]} level :)')
				else:
					die(border, f"The input you provided is not correct!")
		elif ans == 'q':
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == '__main__':
	main()