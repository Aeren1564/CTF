from CTF_Library import *

with remote("challs.pwnoh.io", 13434) as io:
	state = []
	pos = {}
	for _ in range(3):
		peg = []
		while True:
			s = io.readlineS().strip()
			if '|' not in s:
				break
			s = s.split('|')[0]
			if len(s) == 0:
				continue
			pos[len(s)] = len(state)
			peg = [len(s)] + peg
		state.append(peg)

	# move x donuts from a peg to c peg
	def move(a, b, c, x):
		if x == 0:
			return
		move(a, c, b, x - 1)
		io.sendline(str(a + 1).encode())
		io.sendline(str(c + 1).encode())
		move(b, a, c, x - 1)

	for x in range(2, len(pos) + 1):
		if pos[x] != pos[x - 1]:
			move(pos[x - 1], pos[x - 1] ^ pos[x] ^ 3, pos[x], x - 1)

	if pos[len(pos)] != 2:
		move(pos[1], pos[1] ^ 1, 2, len(pos))

	print(io.readallS())
