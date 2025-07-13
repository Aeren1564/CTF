from CTF_Library import *

p = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41882ebea6f6e7b0e959d2c36ba5e27705daffacd9a49b39d5beedc74976b30a260c9
a, b = -7, 0xd3f1356a42265cb4aec98a80b713fb724f44e747fe73d907bdc598557e0d96c5
_n = 0xaeaf714c13bfbff63dd6c4f07dd366674ebe93f6ec6ea51ac8584d9982c41881d942f0dddae61b0641e2a2cf144534c42bf8a9c3cb7bdc2a4392fcb2cc01ef87
x = 0xa0e29c8968e02582d98219ce07dd043270b27e06568cb309131701b3b61c5c374d0dda5ad341baa9d533c17c8a8227df3f7e613447f01e17abbc2645fe5465b0
y = 0x5ee57d33874773dd18f22f9a81b615976a9687222c392801ed9ad96aa6ed364e973edda16c6a3b64760ca74390bb44088bf7156595f5b39bfee3c5cef31c45e1

F = GF(p)
EC = EllipticCurve(F, [a, b])
G = EC(x, y)

# with process(["sage", "Toffee.sage"]) as io:
with remote("91.107.133.165", 31111) as io:
	io.readlines(4)
	def query(k):
		io.readlines(4)
		io.sendline(b"g")
		io.readline()
		io.sendline(str(k).encode())
		return int(io.readlineS().strip().split(" = ")[1])
	def message(m):
		io.readlines(4)
		io.sendline(b"s")
		io.readline()
		io.sendline(m)
		return int(io.readlineS().strip().split(" = ")[1]), int(io.readlineS().strip().split(" = ")[1])
	R = Zmod(_n)
	v = R(query(0))
	u = R(query(1) - v)
	r0, s0 = map(R, message(b""))
	r1, s1 = map(R, message(b""))
	h = R(bytes_to_long(hashlib.sha512(b"").digest()))
	print(long_to_bytes(int((s0 * s1 * v - s0 * h + u * s1 * h) / (s0 * r1 - u * s1 * r0))))

"""
u, v, k: random int in range(1, _n)

query _k -> get (u * _k + v) % _n

given h, and skey which is a function of flag,
r = (k * G).x
s = (h + r * skey) / k mod _n
k <- u * k + v mod _n

u * s1 * s0 * k = u * s1 * h + u * s1 * r0 * skey

s0 * s1 * v + u * s1 * s0 * k = s0 * h + s0 * r1 * skey

s0 * s1 * v = (s0 * h - u * s1 * h) + (s0 * r1 - u * s1 * r0)
"""