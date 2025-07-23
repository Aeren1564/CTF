from CTF_Library import *

with remote("155.248.210.243", 42191) as io:
	io.readuntil(b">")
	io.sendline(b"1")
	enc_flag = long_to_bytes(int(io.readline().strip()))
	enc_flag_l, enc_flag_r = enc_flag[:16], enc_flag[16:]
	def query(a, b):
		io.readuntil(b">")
		io.sendline(b"2")
		io.readuntil(b">")
		io.sendline(str(bytes_to_long(a + b)).encode())
		res = long_to_bytes(int(io.readline().strip()))
		return strxor(res[:16], a), strxor(res[16:], b)
	l, r = query(enc_flag_r, enc_flag_l)
	flag_l = strxor(r, enc_flag_l)
	flag_r = strxor(l, enc_flag_r)

	print(f"{flag_l + flag_r}")

"""
A,
B,
A+E(B),
B+E(A+E(B)),
A+E(B)+E(B+E(A+E(B))),
B+E(A+E(B))+E(A+E(B)+E(B+E(A+E(B))))
A+E(B)+E(B+E(A+E(B)))+E(B+E(A+E(B))+E(A+E(B)+E(B+E(A+E(B)))))
B+E(A+E(B))+E(A+E(B)+E(B+E(A+E(B))))+E(A+E(B)+E(B+E(A+E(B)))+E(B+E(A+E(B))+E(A+E(B)+E(B+E(A+E(B))))))

---------------------------------

f(0, a, b) = a
f(1, a, b) = b
f(2, a, b) = a + E(b)
f(3, a, b) = b + E(a + E(b))

i >= 2
f(i, a, b)
= f(i-2, a, b) + E(f(i-1, a, b))


f(i, a, b) + E(f(i-1, a, b)) + f(i-2, a, b)
"""