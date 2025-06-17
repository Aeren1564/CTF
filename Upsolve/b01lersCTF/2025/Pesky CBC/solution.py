from CTF_Library import *

#with process(["python3", "pesky_cbc.py"]) as io:
with remote("peskycbc.atreides.b01lersc.tf", 8443, ssl = True) as io:
	io.readline()
	f2_secret = int(io.readlineS().strip(), 16)
	io.readline()
	io.readline()
	g1, g2 = {}, {}
	for _ in range(8):
		g2x = int(io.readlineS().strip(), 16)
		x = int(io.readlineS().strip(), 16)
		g2[x] = g2x
	io.readline()
	# Ask for g1(g2(X) + Y) + g2(Y)
	def query(x, y):
		io.readuntil(b">> ")
		io.sendline(b"1")
		io.readuntil(b">> ")
		io.sendline((bytes(16) + long_to_bytes(y, 16) + long_to_bytes(x, 16)).hex().encode())
		return bytes_to_long(bytes.fromhex(io.readlineS().strip())[32 : 48])
	def cheat(x):
		io.readuntil(b">> ")
		io.sendline(b"3")
		io.readuntil(b">> ")
		io.sendline(long_to_bytes(x, 16).hex().encode())
		g1x = int(io.readlineS().strip(), 16)
		g2x = int(io.readlineS().strip(), 16)
		return g1x, g2x
	# g2(x), g2(y) -> g1(x + g2(y))
	def expand_g1(x, y):
		assert x in g2 and y in g2
		z = x ^ g2[y]
		if z not in g1:
			g1[z] = query(y, x) ^ g2[x]
		#assert cheat(z)[0] == g1[z]
		return z, g1[z]
	# g1(x), g2(y) -> g2(x + g2(y))
	def expand_g2(x, y):
		assert x in g1 and y in g2
		z = x ^ g2[y]
		if z not in g2:
			g2[z] = query(y, z) ^ g1[x]
		#assert cheat(z)[1] == g2[z]
		return z, g2[z]
	for it in range(200):
		if it % 10 == 0:
			print(f"{it = }")
		expand_g1(random.choice(list(g2.keys())), random.choice(list(g2.keys())))
		expand_g2(random.choice(list(g1.keys())), random.choice(list(g2.keys())))
	g2_items = list(g2.items())
	g2_values = [g2x << 1 | 1 for x, g2x in g2_items]

	end_x = random.choice(list(g2.keys()))
	start = random.choice(list(g1.keys()))
	end = g2[end_x] ^ f2_secret
	g1_end_plus_secret = query(end_x, f2_secret)

	subset = pick_subset_with_given_xor(g2_values, (start ^ end) << 1)
	assert subset
	assert len(subset) % 2 == 0

	current = start
	for i in range(0, len(subset), 2):
		current = expand_g2(current, g2_items[subset[i + 0]][0])[0]
		current = expand_g1(current, g2_items[subset[i + 1]][0])[0]

	assert current == end
	secret = g1_end_plus_secret ^ g1[end]

	io.readuntil(b">> ")
	io.sendline(b"2")
	io.readuntil(b">> ")
	io.sendline(long_to_bytes(secret, 16).hex().encode())
	print(io.readallS(timeout = 1))

"""
Let
f1(X) = ECB_{Key1}.encrypt(X)
g1(X) = ECB_{Key1}.decrypt(X)
f2(X) = ECB_{Key2}.encrypt(X)
g2(X) = ECB_{Key2}.decrypt(X)
f1, g1, f2, g2 are unknown bijective function from GF(2**128) to itself with f1 * g1 = f2 * g2 = identity

We're given f2(secret)
We're given D[0:8] and E[0:8] where
f2(D[i]) = E[i] <-> g2(E[i]) = D[i]

We can query X, Y to obtain g1(g2(X) + Y) + g2(Y)

Goal is to recover secret
----------------------------------
query(E[i], Y)          -> g1(D[i] + Y) + g2(Y)
query(f2(secret), Y)    -> g1(secret + Y) + g2(Y)
----------------------------------
query(X, E[i])          -> g1(g2(X) + E[i]) + D[i]
query(X, f2(secret))    -> g1(g2(X) + f2(secret)) + secret
----------------------------------

g2(x), g2(y) -> g1(x + g2(y))
g1(x), g2(y) -> g2(x + g2(y))

g1(x), g2(y), g2(z) -> g1(x + g2(y) + g2(z))
"""