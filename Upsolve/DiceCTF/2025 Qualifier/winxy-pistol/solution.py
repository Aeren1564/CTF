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
prefix_live = b"you continue walking. turn to page "
prefix_die = b"you die of "
zero_hash = hashlib.shake_256(bytes(128)).digest(64)
def check_hash(x):
	print(f"Checking hash of {x}")
	with open("in", "w") as f:
		f.write(str(x))
	subprocess.run(["python3", "get_hash.py"])
	with open("out", "rb") as f:
		h = f.read()
		assert len(h) == 64
		return h
with remote("dicec.tf", 31002) as io:
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
		io.sendline(str(x0).encode())
		io.readuntil(b"c0: ")
		c0 = bytes.fromhex(io.readlineS())
		io.readuntil(b"c1: ")
		c1 = bytes.fromhex(io.readlineS())
		d0 = strxor(c0, zero_hash)
		print(f"{d0 = }")
		to_process = ""
		if d0[:len(prefix_live)] == prefix_live:
			to_process = d0[len(prefix_live):]
		else:
			d1 = strxor(c1, check_hash((x0 - x1) % n))
			print(f"{d1 = }")
			assert d1[:len(prefix_live)] == prefix_live
			to_process = d1[len(prefix_live):]
		page = 0
		for c in to_process:
			if not ord('0') <= c <= ord('9'):
				break
			page = page * 10 + c - ord('0')
		return page
	for _ in range(64):
		print(f"Solving #{_}")
		page = solve_once()
		io.readuntil(b"page: ")
		io.sendline(str(page).encode())
	print(io.readallS(timeout = 1.0))
