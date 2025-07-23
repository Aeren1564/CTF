from CTF_Library import *

nbit = 256
e = 1234567891

with open("output.txt") as file:
	n = int(file.readline().split(" = ")[1].strip())
	c = int(file.readline().split(" = ")[1].strip())

cand = [(0, 0)]
for bit in range(2 * nbit):
	mod = 2**(bit + 1)
	cand_next = []
	for q, r in cand:
		if bit < nbit or bit == 2 * nbit - 1:
			q |= 1 << bit
		else:
			q |= (r >> 2 * (bit - nbit) + 1 & 1) << bit
		if ~bit & 1:
			r |= 1 << bit
			if q * r % mod == n % mod:
				cand_next.append((q, r))
		else:
			for _ in range(2):
				if q * r % mod == n % mod:
					cand_next.append((q, r))
				r ^= 1 << bit
	cand = cand_next
	assert len(cand) > 0
for q, r in cand:
	if n == q * r:
		print(long_to_bytes(RSA_decrypt(q, r, e, c)[0]))
		break
