from pwn import *
from CTF_Library import *

#nc = process(["python3", "chal.py"])

nc = remote("root-oracle.chal.crewc.tf", 1337)
print(nc.recvline())

def send(x, y, z):
	nc.sendline(str([x, y, z])[1 : -1].encode())

def recv():
	nc.recvuntil(b"roots=")
	nroots = int(nc.recvline().strip())
	return nroots

def answer(perm):
	nc.sendline(str([-1, -1, -1])[1 : -1].encode())
	nc.sendline(str(perm)[1 : -1].encode())
	nc.recvline()

def solve_level(lvl, stage):
	print(nc.recvline())
	print(nc.recvline())
	print(f"{stage = }")
	n = 100 * lvl + 100
	perm = [-1] * n
	cand = [i for i in range(n)]
	while len(cand) >= 2:
		cand_next = []
		for i in range(0, len(cand), 2):
			if i + 1 != len(cand):
				send(cand[i], cand[i + 1], cand[i])
			else:
				cand_next.append(cand[i])
		for i in range(0, len(cand), 2):
			if i + 1 != len(cand):
				if recv() >= 1:
					cand_next.append(cand[i])
				else:
					cand_next.append(cand[i + 1])
		cand = [i for i in cand_next]
	one = cand[0]
	perm[one] = 1
	order = [one]
	for i in range(n):
		send(one, i, one)
	for i in range(n):
		if recv() == 1:
			perm[i] = 2
			order.append(i)
	while len(order) < n:
		print(f"{len(order) = }")
		for i in range(n):
			if perm[i] == -1:
				send(order[-1], i, order[-1])
		cur = [i for i in range(n) if perm[i] == -1 if recv() <= 1]
		size = len(order)
		order += [0] * len(cur)
		low = [0] * len(cur)
		high = [size - 1] * len(cur)
		while True:
			any_rem = False
			for ind in range(len(cur)):
				if high[ind] - low[ind] >= 2:
					any_rem = True
					p = low[ind] + high[ind] >> 1
					send(order[p], cur[ind], order[p])
			if not any_rem:
				break
			for ind in range(len(cur)):
				if high[ind] - low[ind] >= 2:
					p = low[ind] + high[ind] >> 1
					if recv() == 2:
						low[ind] = p
					else:
						high[ind] = p
		for ind in range(len(cur)):
			p = high[ind]
			send(order[p], cur[ind], order[p])
		for ind in range(len(cur)):
			nroots = recv()
			p, i = high[ind], cur[ind]
			if nroots == 1:
				x = 2 * (p + 1)
				perm[i] = x
				order[x - 1] = i
			else:
				assert nroots == 0
				x = 2 * (p + 1) - 1
				perm[i] = x
				order[x - 1] = i
	answer(perm)
for lvl in range(5):
	for stage in range(2):
		solve_level(lvl, stage)
print(nc.recvline())