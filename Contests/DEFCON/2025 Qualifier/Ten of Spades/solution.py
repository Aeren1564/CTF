from CTF_Library import *

class LCG:
	def __init__(self, seed, m):
		self.s = seed
		self.m = m
		self.c = 0x000007e5
		self.n = 0x7fffffff
	def next(self, ):
		self.s = (self.s * self.m + self.c & 0xffffffff) % self.n
		return self.s
base_deck = "sA s2 s3 s4 s5 s6 s7 s8 s9 sX sJ sQ sK hA h2 h3 h4 h5 h6 h7 h8 h9 hX hJ hQ hK cA c2 c3 c4 c5 c6 c7 c8 c9 cX cJ cQ cK dA d2 d3 d4 d5 d6 d7 d8 d9 dX dJ dQ dK"
def shuffle(seed, m):
	cards = list(base_deck.split(" "))
	order = list(range(len(cards)))
	lcg = LCG(seed, m)
	for i in reversed(range(len(order))):
		j = lcg.next() % (i + 1)
		order[i], order[j] = order[j], order[i]
	cards = [cards[i] for i in order]
	return cards

ticket = "ticket{WallaceBluey127n25:CZ8V3_WtsG6s1GAc6GaJiW6DzCcvc_e3U9f3ExLlbLNkK6wu}"
with open("output.txt", "w") as file:
	with remote("tenspades-vyl6gsuoz7nky.shellweplayaga.me", 1337) as io:
		io.readuntil(b": ")
		io.sendline(ticket.encode())
		io.readlinesS(2)
		for it in range(20):
			print(f"{it = }")
			seed = int(io.readlineS().strip().split(": ")[1], 16)
			print(f"{seed = }")
			io.readlineS().strip()
			io.sendline(base_deck.encode())
			io.readlineS()
			res = list(io.readlineS().strip().split(" "))
			line = str(seed) + " "
			for i in range(52):
				index = list(base_deck.split(" ")).index(res[i])
				line += str(index)
				if i != 51:
					line += " "
			line += "\n"
			file.write(line)

subprocess.run(["time", "./recover"])

with open("m.txt", "r") as file:
	m = int(file.readline().strip())

with remote("tenspades-vyl6gsuoz7nky.shellweplayaga.me", 1337) as io:
	io.readuntil(b": ")
	io.sendline(ticket.encode())
	print(io.readlinesS(2))
	seed = int(io.readlineS().strip().split(": ")[1], 16)
	print(f"{seed = }")
	print(io.readlineS().strip())
	res = shuffle(seed, m)
	print(base_deck)
	io.sendline(" ".join(res).encode())
	print(io.readallS(timeout = 1))
