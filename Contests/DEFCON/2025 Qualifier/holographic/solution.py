from CTF_Library import *

base_deck_str = "sA s2 s3 s4 s5 s6 s7 s8 s9 sX sJ sQ sK hA h2 h3 h4 h5 h6 h7 h8 h9 hX hJ hQ hK cA c2 c3 c4 c5 c6 c7 c8 c9 cX cJ cQ cK dA d2 d3 d4 d5 d6 d7 d8 d9 dX dJ dQ dK"
base_deck = list(base_deck_str.split(" "))

ticket = "ticket{SugarTabby7041n25:V1A45Z6r81bwec9QthLDVSGzMg1O3VGfT-zDBVV9AVEVJtXn}"
with open("remote_output.txt", "w") as file:
	with remote("holographic-23seeordn6w4k.shellweplayaga.me", 1337) as io:
		io.readuntil(b": ") # Ticket please:
		io.sendline(ticket.encode())
		io.readlines(2) # holographic\n base_deck_str
		for it in range(50):
			io.readline() # empty
			print(f"{it = }")
			seed = int(io.readlineS().strip().split(": ")[1], 16)
			print(f"{seed = }")
			io.readlineS().strip() # show me your cards
			io.sendline(base_deck_str.encode())
			io.readlineS() # Oh no, were you bluffing too?
			res = list(io.readlineS().strip().split(" "))
			line = str(seed) + " "
			for i in range(52):
				index = base_deck.index(res[i])
				line += str(index)
				if i != 51:
					line += " "
			line += "\n"
			file.write(line)

subprocess.run(["time", "./recover"])

with open("env_seed.txt", "r") as file:
	env_seed = int(file.readline().strip())

with remote("holographic-23seeordn6w4k.shellweplayaga.me", 1337) as io:
	io.readuntil(b": ") # Ticket please:
	io.sendline(ticket.encode())
	io.readlinesS(2) # holographic\n base_deck_str
	io.readline() # empty
	seed = int(io.readlineS().strip().split(": ")[1], 16)
	io.readlineS().strip() # show me your cards
	with open("input.txt", "w") as file:
		file.write(str(env_seed) + "\n" + str(seed) + "\n")
	subprocess.run(["time", "./get_output"])
	with open("output.txt", "r") as file:
		deck_index = list(map(int, file.read().strip().split(" ")))
		deck = [base_deck[i] for i in deck_index]
	print(f"{deck = }")
	io.sendline(" ".join(deck).encode())
	print(io.readallS(timeout = 2))
