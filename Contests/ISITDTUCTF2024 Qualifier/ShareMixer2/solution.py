from CTF_Library import *

while True:
	with remote("35.187.238.100", 5002) as io:
		p = int(io.readlineS().strip().split("= ")[1])
		print(f"{p = }")
		F = GF(p)
		x = polygen(F)
		io.readuntil(b"Gib me the queries: ")
		q = []
		for root in (x**32 - 1).roots(multiplicities = false):
			q.append(int(root))
		print(f"{len(q) = }")
		if len(q) != 32:
			continue
		io.sendline(" ".join(map(str, q)).encode())
		flag = long_to_bytes(int(sum(map(F, literal_eval(io.readlineS().strip().split("= ")[1]))) / 32))
		print(f"{flag = }")
		if b"ISITDTU{" in flag:
			break
