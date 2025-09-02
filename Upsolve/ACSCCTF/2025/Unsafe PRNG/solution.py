from CTF_Library import *



outputs = []
with remote("host1.dreamhack.games", 23421) as io:
	io.readuntil(b": ")
	n = int(io.readlineS().strip(), 16)
	R = Zmod(n)
	X = R['X'].gen()
	for _ in range(4):
		io.sendlineafter(b">>> ", b"1")
		io.sendlineafter(b">>> ", bytes([0] * 93))
		io.readuntil(b": ")
		enc = int(io.readlineS().strip(), 16)
		poly = (2**(8 * 126 + 1) + X * 2**(8 * 94))**3 - enc
		outputs += list(long_to_bytes(int(poly.monic().small_roots(2**256)[0]), 32))
with remote("host1.dreamhack.games", 23421) as io:
	io.readuntil(b": ")
	assert n == int(io.readlineS().strip(), 16)
	io.sendlineafter(b">>> ", b"2")
	io.readuntil(b": ")
	enc = int(io.readlineS().strip(), 16)
	prefix = bytes_to_long(bytes(outputs[:93]))
	poly = (2**(8 * 126 + 1) + prefix * 2**(8 * 33) + X)**3 - enc
	flag = long_to_bytes(int(poly.monic().small_roots(2**256, beta = 1, epsilon = 0.1)[0]), 32)
	print(flag)
