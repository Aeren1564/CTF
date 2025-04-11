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

for cause in DEATH_CAUSES:
	assert len(prefix_die) + len(cause) + 1 <= len(prefix_live)

with open("in", "r") as f:
	x = int(f.readline())
cnt = defaultdict(int)
opt_cnt = -1
while True:
	with remote("dicec.tf", 31002) as io2:
		io2.readuntil(b"n: ")
		n = int(io2.readlineS())
		io2.readuntil(b"e: ")
		e = int(io2.readlineS())
		io2.readuntil(b"x0: ")
		x0 = int(io2.readlineS())
		io2.readuntil(b"x1: ")
		x1 = int(io2.readlineS())
		io2.readuntil(b"v: ")
		io2.sendline(str((x + x0) % n).encode())
		io2.readuntil(b"c0: ")
		c0 = bytes.fromhex(io2.readlineS())
		cnt[c0[:len(prefix_live)]] = cnt[c0[:len(prefix_live)]] + 1
		opt_cnt = max(opt_cnt, cnt[c0[:len(prefix_live)]])
		if opt_cnt == 4:
			break
res = b""
for key, key_cnt in cnt.items():
	if key_cnt == opt_cnt:
		res = strxor(prefix_live, key)
		break
assert len(res) == len(prefix_live)
while True:
	with remote("dicec.tf", 31002) as io2:
		io2.readuntil(b"n: ")
		n = int(io2.readlineS())
		io2.readuntil(b"e: ")
		e = int(io2.readlineS())
		io2.readuntil(b"x0: ")
		x0 = int(io2.readlineS())
		io2.readuntil(b"x1: ")
		x1 = int(io2.readlineS())
		io2.readuntil(b"v: ")
		io2.sendline(str((x + x0) % n).encode())
		io2.readuntil(b"c0: ")
		c0 = bytes.fromhex(io2.readlineS())
		if c0[:len(prefix_die)] == strxor(prefix_die, res[:len(prefix_die)]):
			for cause in DEATH_CAUSES:
				if c0[:len(prefix_die) + len(cause) + 1] == strxor(prefix_die + cause.encode() + b".", res[:len(prefix_die) + len(cause) + 1]):
					res = strxor(c0, prefix_die + cause.encode() + b"." + bytes(64 - len(prefix_die) - len(cause) - 1))
					break
			else:
				assert False
			break
with open("out", "wb") as f:
	f.write(res)