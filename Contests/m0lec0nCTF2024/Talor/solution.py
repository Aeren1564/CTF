from pwn import *
import os
import multiprocessing as mp
from random import randrange
import itertools
from collections import Counter

p = 241
SB = [31, 32, 57, 9, 31, 144, 126, 114, 1, 38, 231, 220, 122, 169, 105, 29, 33, 81, 129, 4, 6, 64, 97, 134, 193, 160, 150, 145, 114, 133, 23, 193, 73, 162, 220, 111, 164, 88, 56, 102, 0, 107, 37, 227, 129, 17, 143, 134, 76, 152, 39, 233, 0, 147, 9, 220, 182, 113, 203, 11, 31, 125, 125, 194, 223, 192, 49, 71, 20, 227, 25, 38, 132, 17, 90, 109, 36, 157, 238, 127, 115, 92, 149, 216, 182, 15, 123, 28, 173, 114, 86, 159, 117, 60, 42, 191, 106, 182, 43, 108, 24, 232, 159, 25, 240, 78, 207, 158, 132, 156, 203, 71, 226, 235, 91, 92, 238, 110, 195, 78, 8, 54, 225, 108, 193, 65, 211, 212, 68, 77, 232, 100, 147, 171, 145, 96, 225, 63, 37, 144, 71, 38, 195, 19, 121, 197, 112, 20, 2, 186, 144, 217, 189, 130, 34, 180, 47, 121, 87, 154, 211, 188, 176, 65, 146, 26, 194, 213, 45, 171, 24, 37, 76, 42, 232, 13, 111, 80, 109, 178, 178, 31, 51, 100, 190, 121, 83, 53, 156, 62, 70, 23, 151, 227, 169, 160, 45, 174, 76, 25, 196, 62, 201, 6, 215, 139, 192, 83, 141, 230, 110, 39, 170, 189, 158, 153, 143, 110, 169, 206, 239, 56, 58, 174, 222, 29, 33, 198, 134, 181, 83, 72, 24, 61, 189, 177, 159, 31, 53, 5, 30]
state_size = 32
r = 16
c = state_size - r
ROUNDS = 140

def absorb(state, rc, rounds = ROUNDS):
	state = state[:]
	tmps = [0] * rounds
	for i in range(rounds):
		tmp = SB[(state[0] + rc[i]) % p]
		tmps[i] = tmp
		for j in range(1, len(state)):
			state[j] += tmp
			state[j] %= p
		state = state[1:] + state[:1]
	return tmps, state

def sponge(payload, rc):
	assert len(payload) % r == 0
	state = [0] * state_size
	for i in range(0, len(payload), r):
		state = [(state[j] + payload[i+j]) % p for j in range(r)] + state[r:]
		state = absorb(state, rc)[1]
	return state[ : 12]

def h(msg, rc):
	m = msg[:]
	m.append(len(m))
	if len(m) % r != 0:
		m += [0] * (r - (len(m) % r))
	return sponge(m, rc)

with process(["py3", "chall.py"]) as nc:
	for _ in range(10):
		print(nc.recvlineS())
		nc.readuntil(b"rc = ")
		rc = eval(nc.readlineS())

		def bruteforce(rc):
			base = [randrange(p) for _ in range(16)] + [0] * 16
			found = [None] * p
			for x in range(p):
				base[12] = x
				found[x] = bytes(absorb(base, rc, 13 + 32 * 3)[0][12 : : 32])
			key, cnt = Counter(found).most_common()[0]
			if cnt >= 2:
				return base, [x for x in range(p) if bytes(found[x]) == key]
			else:
				return base, None 

		def search(rc):
			attempt = 0
			with mp.Pool(os.cpu_count()) as pool:
				for base, values in pool.imap_unordered(bruteforce, itertools.repeat(rc)):
					attempt += 1
					if values is not None:
						print(f"{attempt = }")
						pool.terminate()
						assert len(values) >= 2
						m1 = base[0 : 12] + [values[0]] + base[13 : 16]
						m2 = base[0 : 12] + [values[1]] + base[13 : 16]
						return m1, m2

		m1, m2 = search(rc)
		h1, h2 = sponge(m1, rc), sponge(m2, rc)
		
		assert all(i == 0 or h1[i] == h2[i] for i in range(12))
		m1 += [0]
		m2 += [(h1[0] - h2[0]) % p]
		assert h(m1, rc) == h(m2, rc)
		nc.sendlineafter(b"M1: ", bytes(m1).hex().encode())
		nc.sendlineafter(b"M2: ", bytes(m2).hex().encode())

	print(nc.readlineS())
