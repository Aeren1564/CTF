from CTF_Library import *

DEATH_CAUSES = [
	'a fever',
	'dysentery',
	'measles',
	'cholera',
	'typhoid',
	'exhaustion',
	'a snakebite',
	'a broken leg',
	'a broken arm',
	'drowning',
]
prefix_live = "you continue walking. turn to page "
prefix_die = "you die of "

with remote("dicec.tf", 31001) as io:
	def solve_once():
		io.readuntil(b"n: ")
		n = int(io.readlineS())
		io.readuntil(b"e: ")
		e = int(io.readlineS())
		io.readuntil(b"x0: ")
		x0 = int(io.readlineS())
		io.readuntil(b"x1: ")
		x1 = int(io.readlineS())
		io.readuntil(b"v: ")
		v = (x0 + x1) * (n + 1) // 2 % n
		io.sendline(str(v).encode())
		io.readuntil(b"c0: ")
		c0 = int(io.readlineS())
		io.readuntil(b"c1: ")
		c1 = int(io.readlineS())
		for _ in range(2):
			# 0: live, 1: death
			for d in range(1, 15):
				live = "you continue walking. turn to page " + '0' * d + "."
				m0 = int.from_bytes(live.encode(), "big")
				for cause in DEATH_CAUSES:
					die = f"you die of {cause}."
					m1 = int.from_bytes(die.encode(), "big")
					dif = (c0 + c1 - m0 - m1) % n
					k0 = (c0 - m0 - dif) % n
					k1 = (c1 - m1) % n
					if pow(k0, e, n) != (v - x0) % n or pow(k1, e, n) != (v - x1) % n:
						continue
					if dif >= 256**(d + 1) or dif % 256 != 0:
						continue
					page = 0
					for i in reversed(range(d)):
						x = dif // 256**(i + 1) % 256
						if x >= 10:
							break
						page = 10 * page + x
					else:
						return page
			x0, x1 = x1, x0
			c0, c1 = c1, c0
		assert False
	for _ in range(64):
		print(f"Solving #{_}")
		page = solve_once()
		io.readuntil(b"page: ")
		io.sendline(str(page).encode())
	print(io.readallS(timeout = 1.0))
