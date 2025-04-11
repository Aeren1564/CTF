from CTF_Library import *

n = 112
a = [0] * n
for i in range(n):
	a[i] = random.randrange(2**64) | 1 << 11

def v8ToDouble(state0):
	return (state0 >> 11) / (1 << 53)

import struct
def nodeToDouble(state0):
	# Exponent for double values for [1.0 .. 2.0)
	kExponentBits = 0x3FF0000000000000
	random = (state0 >> 12) | kExponentBits
	# Convert to bytes and unpack as double
	packed = struct.pack('Q', random)
	unpacked = struct.unpack('d', packed)
	return unpacked[0] - 1.0

def count_dif(k):
	assert 0 <= k <= 4600000000000000
	cnt = 0
	for i in range(n):
		cnt += 1 if int(floor(v8ToDouble(a[i]) * k)) != int(floor(nodeToDouble(a[i]) * k)) else 0
	return cnt

from fractions import Fraction
import math

def semiconvergents(a, b, max_k=None):
	x = a
	cf = []
	while True:
		a0 = int(x)
		cf.append(a0)
		x = x - a0
		if x == 0:
			break
		x = 1 / x

		# Generate convergents (p/q)
		n = len(cf)
		p0, q0 = 1, 0
		p1, q1 = cf[0], 1

		for i in range(1, n):
			b = cf[i]
			p0, p1 = p1, b * p1 + p0
			q0, q1 = q1, b * q1 + q0

		yield (p1, q1)  # actual convergent

		if len(cf) < 2:
			continue

		# Generate semiconvergents between last two convergents
		a_next = cf[-1]
		for m in range(1, a_next):
			p = m * p1 + p0
			q = m * q1 + q0
			yield (p, q)
			if max_k and q > max_k:
				return

def ks_with_integer_in_ka_kb_via_semiconvergents(a, b, max_k=4600000000000000):
	if a > b:
		a, b = b, a
	assert a < b
	for p, q in semiconvergents(a, b, max_k):
		ka = a * q
		kb = b * q
		if math.ceil(ka) <= math.floor(kb):
			yield q

conv = []
for i in range(n):
	conv.append(min(ks_with_integer_in_ka_kb_via_semiconvergents(v8ToDouble(a[i]), nodeToDouble(a[i]))))

print(conv)

y = None
for x in conv:
	cur = 10000000 * x
	if count_dif(cur) >= 1 and count_dif(cur + 1) >= 1:
		y = cur
		break
if y is None:
	print(f"Fail :(")
	exit(0)
x = y
streak = 0
opt = 0
while count_dif(x + streak) >= 1:
	opt = max(opt, count_dif(x + streak))
	streak += 1
print(f"{opt = }")
print(f"{streak = }")
print(count_dif(x))
print(count_dif(x + 1))
print(count_dif(x + 2))