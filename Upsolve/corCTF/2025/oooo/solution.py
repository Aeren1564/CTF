from CTF_Library import *

with remote("ctfi.ng", 31556) as io:
	io.readline()
	flag = [[c] for c in b"corctf{"] + [list(range(256)) for _ in range(49)]
	attempt = 0
	while any(len(x) >= 2 for x in flag):
		attempt += 1
		print(f"Attempt #{attempt}")
		io.sendline()
		enc = bytes.fromhex(io.readlineS().strip())
		for i in range(7):
			for j in range(7, 56):
				x = flag[i][0] ^ enc[i] ^ enc[j]
				if x in flag[j]:
					print(f"Removing {x} from {j}")
					flag[j].remove(x)
	print(bytes(x[0] for x in flag))
