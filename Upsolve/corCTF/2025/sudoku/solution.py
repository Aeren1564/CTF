from CTF_Library import *
from commitment import *

fake_solution = [
	[1, 2, 3,  0, 4, 5,  6, 7, 8],
	[4, 0, 5,  7, 6, 8,  1, 2, 3],
	[7, 6, 8,  1, 2, 3,  0, 4, 5],

	[0, 3, 4,  5, 8, 2,  7, 1, 6],
	[6, 1, 7,  3, 0, 4,  8, 5, 2],
	[8, 5, 2,  6, 1, 7,  4, 3, 0],

	[2, 8, 0,  4, 3, 1,  5, 6, 7],
	[3, 7, 1,  8, 5, 6,  2, 0, 4],
	[5, 4, 6,  2, 7, 0,  3, 8, 1],
]

colors = [str(c // 2) if c % 2 else str(c // 2) + "-" for c in range(9)]

color_reveals = [make_reveal_entry(colors[c], pow(-1, c)) for c in range(9)]

graph = commitment_to_json([color_reveals[0]["commitment"] for _ in range(90)]).encode()

colors = commitment_to_json(colors).encode()

reveal = reveal_to_json([color_reveals[0], color_reveals[1]]).encode()

# with process(["python3", "server.py"]) as io:
with remote("ctfi.ng", 31122) as io:
	io.readlines(6)
	for i in range(0, 8192, 64):
		print(f"{i = }")
		for j in range(64):
			io.sendline(graph)
			io.sendline(colors)
			io.sendline(reveal)
		io.readlines(64 * 7)
	print(io.readallS(timeout = 1))
