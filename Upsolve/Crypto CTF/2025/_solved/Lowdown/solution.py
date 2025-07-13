from CTF_Library import *

F = GF(256)
k = 10

def h(a):
	if a == 0:
		return 0
	else:
		g = F.gen()
		for _ in range(1, 256):
			if g ** _ == a:
				return _

def H(M):
	assert M.nrows() == M.ncols()
	k, _H = M.nrows(), []
	for i in range(k):
		for j in range(k):
			_h = h(M[i, j])
			_H.append(bin(_h)[2:].zfill(8))
	return ''.join(_H)

def Hinv(m):
	global k
	B = bin(m)[2:].zfill(8 * k**2)
	g = F.gen()
	_H = [int(B[8*i:8*i + 8], 2) for i in range(k**2)]
	_M = [0 if _h == 0 else g ** _h for _h in _H]
	M = Matrix(F, [[a for a in _M[k*i:k*i + k]] for i in range(k)])
	return M

def M2i(M):
	_H = H(M)
	return int(_H, 2)

def random_oracle(msg):
	from hashlib import sha1
	_h = sha1(msg).digest()
	return bytes_to_long(_h)

def verify(sgn, pkey, msg):
	_, ga = pkey
	s, t = sgn
	_h = random_oracle(msg)
	return s * t ** _h == ga

# with process(["sage", "lowdown.sage"]) as io:
with remote("91.107.132.34", 31113) as io:
	io.readlines(4)
	def get_pkey():
		io.readlines(6)
		io.sendline(b"p")
		g = Hinv(int(io.readlineS().strip().split(" = ")[1]))
		ga = Hinv(int(io.readlineS().strip().split(" = ")[1]))
		return g, ga
	g, ga = get_pkey()
	io.readlines(6)
	io.sendline(b"g")
	io.readline()
	msg = ast.literal_eval(io.readlineS().strip().split(" = ")[1])
	io.readline()
	while True:
		t = str(random.getrandbits(8 * k**2))
		t = "37" + t[2:]
		t = int(t)
		assert str(t).startswith("37")
		tm = Hinv(t)
		if not tm.is_invertible():
			continue
		s = M2i(ga / Hinv(t)**random_oracle(msg))
		if str(s).startswith("13"):
			break
	assert verify((Hinv(s), Hinv(t)), (g, ga), msg)
	io.sendline(",".join([str(s), str(t)]).encode())
	print(io.readallS(timeout = 1))

"""
k = 10
F = GF(256)
H(mat): converts each element in mat to discrete log
Hinv(mat): converts each element x in mat to gen**x

<public key>
g (k by k matrix over F)
ga (which is a power of g)
ng = 2**192 (order of g)

<sign(skey, m)>
_g = g**skey
k <- random int (hidden)
s = ga / g**(skey * k * m)
t = g**(skey * k)

<verify((s, t), m)>
s * t**m == ga
"""