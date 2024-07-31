from sage.all import *
import output

n = output.n
MASK = output.MASK
stream_key = output.stream[0 : 2048]
stream_flag = output.stream[2048 : ]

vec = [1] + [0] * (n - 1)
transition = []
for i in range(n - 1):
	transition.append((i, i + 1))
for j in range(n):
	if (MASK >> j) & 1:
		transition.append((n - 1, j))

def next_coef(vec):
	vec_next = [0] * n
	for i, j in transition:
		vec_next[j] ^= vec[i]
	return vec_next

vec2 = vec
for _ in range(n):
	vec2 = next_coef(vec2)

mat = []
value = []
for i in range(len(stream_key) - 1):
	s, t = stream_key[i], stream_key[i + 1]
	candidate = []
	for x in range(2):
		for y in range(2):
			if (x - s - y) % 3 == t:
				candidate.append((x, y))
	if len(candidate) == 1:
		x, y = candidate[0]
		mat.append(vec)
		value.append(x)
		mat.append(vec2)
		value.append(y)
	vec = next_coef(vec)
	vec2 = next_coef(vec2)
key_vec = matrix(GF(2), mat).solve_right(vector(GF(2), value))

print(f"{key_vec = }")

key = sum([int(key_vec[i]) << i for i in range(n)])

class LF3R:
	def __init__(self, n, key, mask):
		self.n = n
		self.state = key & ((1 << n) - 1)
		self.mask = mask

	def __call__(self):
		v = self.state % 3
		self.state = (self.state >> 1) | (
			(bin(self.state & self.mask).count('1') & 1) << (self.n - 1)
		)
		return v

lf3r = LF3R(n, key, MASK)

for _ in range(2048):
	lf3r()

flag_vec = []
for x in stream_flag:
	flag_vec.append((x - lf3r()) % 3)

flag = 0
for x in reversed(flag_vec):
	flag = 3 * flag + x

print(flag.to_bytes(50, "big"))
