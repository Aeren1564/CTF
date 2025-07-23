from CTF_Library import *

nbit = 512
e = 65537
charset = string.printable[:63] + '_{-}'

# with process(["python3", "ASIS_Primes.py"]) as io:
with remote("91.107.133.165", 13737) as io:
	io.readlines(4)

	for _ in range(800 - nbit):
		io.sendline(b"s")
		io.sendline(b"?,?,?")
	io.readlines(8 * (800 - nbit))
	nbit = 800

	io.readlines(4)
	io.sendline(b"s")
	pinit = ast.literal_eval(io.readlineS().strip().split(": ")[1]).decode()
	qinit = ast.literal_eval(io.readlineS().strip().split(": ")[1]).decode()
	io.readline()
	while True:
		while True:
			p = bytes_to_long((pinit[:] + "".join(random.sample(charset, nbit // 8 - len(pinit) - 1)) + "}").encode())
			if is_prime(p):
				break
		while True:
			q = bytes_to_long((qinit[:] + "".join(random.sample(charset, nbit // 8 - len(qinit) - 1)) + "}").encode())
			if is_prime(q):
				break
		assert (9 * p * q).bit_length() == 2 * nbit
		break
	print(f"{p = }")
	print(f"{q = }")
	io.sendline((str(p) + "," + str(q)).encode())
	io.readlines(4)
	io.sendline(b"e")
	c = int(io.readlineS().strip().split(" = ")[1])
	for x in RSA_decrypt(p, q, e ^ 1, c):
		flag = long_to_bytes(x)
		if flag.startswith(b"CCTF{"):
			print(flag)
			exit()

"""
bit length of p: 999
product bit length: 2000
nbit 1000
"""