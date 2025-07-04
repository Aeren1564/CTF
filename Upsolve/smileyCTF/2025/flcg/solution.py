from sage.all import *
from Crypto.Util.number import *
from Crypto.Cipher import AES
import random
from tqdm import tqdm

c = bytes.fromhex("672c81f887ac08cebf06b106114563695a14ce1717fa3973bc6b1d810ad25c3c")
bs = [c[i:i+8] for i in range(0, len(c), 8)]
assert len(bs) == 4
bs = [int.from_bytes(b, 'big') for b in bs]

p = 2**64 - 59

def recover_state(b):
	n = b * pow(2, -512+58, p) % p
	return n << (512-58)

def v2p(n):
	i = 0
	while i < 20000:
		if n % (2**(i+1)) != 0:
			return i
		i += 1

states = [recover_state(b) for b in bs]
NBIT = min(v2p(states[0]), v2p(states[1]), v2p(states[2]), v2p(states[3]))
assert all(s % (2**NBIT) == 0 for s in states)
print(NBIT)

def find_m():
	M = matrix(ZZ, [[states[0]>>(NBIT-3), 1, 0, 0], [states[1]>>(NBIT-3), 0, 1, 0],[states[2]>>(NBIT-3), 0, 0, 1]])
	M = M.LLL()
	print(M)

	GUESS_BIT = 501 # need to guess this bit

	us = [(states[1] * v[0] + states[2] * v[1] + states[3] * v[2]) >> NBIT for v in M[:, 1:]]

	M2 = matrix(QQ, [[us[0]*2**128, 1, 0, 0], [us[1]*2**128, 0, 1, 0],[us[2]*2**128, 0, 0, 1]])
	M2 = M2.LLL()
	M2.rescale_col(0, QQ(1)/(2**128))
	print(M2)

	v1 = M2[0][1:]
	v2 = M2[1][1:]

	search_space1 = [(a, b) for a in range(120) for b in range(-120, 120)]
	search_space1 = filter(lambda x: gcd(x[0], x[1]) == 1, search_space1)
	search_space1 = sorted(search_space1, key=lambda x: abs(x[0]) + abs(x[1]))

	search_space2 = [(a, b) for a in range(-120, 120) for b in range(-120, 120)]
	search_space2 = sorted(search_space2, key=lambda x: abs(x[0]) + abs(x[1]))

	for rr1, rr2 in tqdm(search_space1):
		guess_v = rr2 * v1 - rr1 * v2

		M3 = matrix(ZZ, [[guess_v[0]*2**128, 1, 0, 0], [guess_v[1]*2**128, 0, 1, 0],[guess_v[2]*2**128, 0, 0, 1]])
		M3 = M3.LLL()
		M3 = M3[:2, 1:]

		for a, b in search_space2:
			rrr = a*M3[0] + b*M3[1]
			for ooo in range(4):
				j0 = (rrr[0] << (GUESS_BIT+ooo)) + us[0]
				j1 = (rrr[1] << (GUESS_BIT+ooo)) + us[1]
				j2 = (rrr[2] << (GUESS_BIT+ooo)) + us[2]
				if gcd(gcd(j0, j1), j2).bit_length() > 32:
					print(f"Found: {a}, {b}", rr1, rr2, rrr, us)
					print(gcd(gcd(j0, j1), j2))
					return gcd(gcd(j0, j1), j2)<<NBIT

m = find_m()

def find_a():
	def check(a):
		try:
			for i in range(3):
				s1 = int(float(states[i]*a)) % m
				if s1 != states[i+1]:
					return False
			return True
		except OverflowError:
			return False

	for GUESS_BIT2 in range(960, 980):
	# for DEBUG_BIT2 in [v2p(int(float(states[0]*debug_a)))]:
		s1 = states[1] >> NBIT
		s0 = states[0] >> NBIT
		m0 = m >> NBIT
		u = s1 * pow(2, -(GUESS_BIT2-NBIT), m0) % m0
		while u < 2**53:
			guess_a = int(float(u)/s0*2**52)
			# print(u, guess_a)
			u += m0
			guess_a = guess_a >> v2p(guess_a)
			for B in range(440, 475):
				if check(guess_a<<B):
					print("Found a:", guess_a)
					return guess_a << B

a = find_a()

def get_last_state(state, a,m):
	m0 = m >> NBIT
	s1 = state >> NBIT
	a0 = a >> v2p(a)
	possible_states = []
	for BIT in range(500, 520):
		u = s1 * pow(2, -BIT, m0) % m0
		while u < 2**53:
			guess_state = int(float(u)/a0*2**52)
			guess_state = guess_state >> v2p(guess_state)
			for BIT2 in range(450, 480):
				guess_state2 = guess_state << BIT2
				if guess_state2 * a > 2**1024:
					continue
				if int(float(guess_state2 * a)) % m == state:
					possible_states.append(guess_state2)
			u += m0
	return possible_states

pairs = []
ss2_list = get_last_state(states[0], a, m)
for ss2 in ss2_list:
	ss1_list = get_last_state(ss2, a, m)
	for ss1 in ss1_list:
		pairs.append((ss1, ss2))

def get_number(x):
	return x % (2**64 - 59)

ct = bytes.fromhex("5c285fcff21cadb30a6ec92d445e5d75898f83fc31ff395cb43fb8be319d464895cf9aed809c20f92eb6f79f6bd36fc8d3091725b54c889a22850179ec26f89c")
for ss1, ss2 in pairs:
	key = b''.join([get_number(ss1).to_bytes(8, 'big'), get_number(ss2).to_bytes(8, 'big')])
	cipher = AES.new(key, AES.MODE_ECB)
	pt = cipher.decrypt(ct)
	if pt.startswith(b".;,;.{"):
		print("Found flag:", pt)
		break

# .;,;.{what_is_there_not_to_like_about_floats?_9572ba8ce501}