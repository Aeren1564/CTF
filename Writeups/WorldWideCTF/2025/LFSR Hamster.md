# `chall.py`

```python
from flag import flag
import os

assert flag[:4] == b"wwf{" and flag[-1:] == b"}"

class LFSRHamster:
	def __init__(self, key):
		self.state = [int(eb) for b in key for eb in bin(b)[2:].zfill(8)]
		self.taps = [0, 1, 2, 7]
		self.filter = [85, 45, 76, 54, 45, 35, 39, 37, 117, 13, 112, 64, 75, 117, 21, 40]
		for _ in range(128):
			self.clock()

	def xorsum(self, l):
		s = 0
		for x in l:
			s ^= x
		return s
	
	def hamster(self, l):
		return l[min(sum(l), len(l) - 1)]

	def clock(self):
		x = [self.state[i] for i in self.filter]
		self.state = self.state[1:] + [self.xorsum(self.state[p] for p in self.taps)]
		return self.hamster(x)
	
	def encrypt(self, data):
		c = []
		for p in data:
			b = 0
			for _ in range(8):
				b = (b << 1) | self.clock()
			c += [p ^ b]
		return bytes(c)
	
if __name__ == "__main__":    
	H = LFSRHamster(os.urandom(16))

	while True:
		t = input(">")
		if t == "flag":
			print(H.encrypt(flag).hex())
		elif t == "enc":
			p = bytes.fromhex(input(">"))
			print(H.encrypt(p).hex())
```

# Solution

If `hamster` choose the same indices for output bits $\lbrace i, i+1, i+2, i+7, i+128 \rbrace$ for some integer $i \ge 0$, the xor of output values at those bits must be $0$. Otherwise, we expect the xor to be $0$ or $1$ uniformly at random.

The probability $p$ that the xor is $0$ for any $i$ can be estimated with the above assumption as follows,
```python
cnt = [0] * 16
for mask in range(1 << 14):
	x = 0
	for i in range(14):
		if mask >> i & 1:
			x += 1 if i < 12 else 2
	cnt[min(x, 15)] += 1
p = 0
for x in cnt:
	p += (x / 2**14)**5
p = p + (1 - p) / 2
print(f"{p = }")
```
which gives $p = 0.5002062218503432$.
Note that the actual probability seems to be higher than this, around $0.5004$. I'm happy to hear it if anyone knows how to obtain this more accurate estimation.

We can now recover the flag bit by bit in increasing order of index. We align $i+128$ with the unknown flag bit, and each of $i, i+1, i+2, i+7$ with either a zero bit, or a known flag bit. We sample this data $n$ times, count how many $0$ and $1$ appear as the xor of these $5$ bits, and set the unknown flag bit to whichever bit occurs more.

You can find the suitable value of $n$ by running the following mini-simulation, and set $n$ to be large enough to suceed almost always.
```python
import random

n = 2 * 10**7
p = 0.5002062218503432

history = [0, 0]
while True:
	cnt = [0, 0]
	for _ in range(n):
		cnt[random.random() < p] += 1
	if cnt[0] < cnt[1]:
		history[1] += 1
		print(f"OK {cnt = }")
	else:
		history[0] += 1
		print(f":( {cnt = }")
	print(f"{history = }")
	print()
```
I used $n = 2 \cdot 10^7$ during the competition, though $n=10^7$ seems to be enough for the more accurate estimation of probability.

These are enough to solve this challenge. However, for the sake of completeness, I will attach a small analysis of success probability of this strategy.

The count $X$ of $0$ follows the binomial distribution $\mathcal{B}(n, p)$, which approaches the normal distribution $\mathcal{N}(n p, n p (1-p))$ as $n$ increases, by the De Moivre–Laplace theorem.

Let $Z$ be a random variable following the standard normal distribution $\mathcal{N}(0, 1)$, and $\Phi$ be the cumulative distribution function of $\mathcal{N}(0, 1)$. Then

$$
\mathbb{P}\left(X > \frac{n}2 \right) \approx 1-\mathbb{P}\left(Z \le -\frac{p - 0.5}{\sqrt{p(1-p)}}\sqrt{n} \right) = 1 - \Phi\left( -\frac{p - 0.5}{\sqrt{p(1-p)}}\sqrt{n} \right)
$$

The following function estimates the probability that this strategy recovers a single bit correctly.

```python
def success_probability(n, p):
	from math import erf, sqrt
	def phi(x):
		return (1 + erf(x / sqrt(2))) / 2
	return 1 - phi(-(p - 0.5) / sqrt(p * (1 - p)) * sqrt(n))
```

The followings are estimated probability of success for two choices of parameters.
- For parameters $n = 2 \cdot 10^7, p=0.5002062218503432$, which I used during contest, the estimation is $0.9674451717873864$
- For parameters $n = 10^7, p=0.5004$, which seems more accurate according to my testing, the estimation is $0.9942939949715881$

# Implementation

The following implementation solves the challenge locally within a reasonable time, but it will be too slow on the remote. I ran 20 connections in parallel and combined the result in order to speed it up during contest.

```python
from pwn import *

flag_len = 8 * 21 # 21 bytes
n = 2 * 10**7
connection_chunk = 10**4
chunk = 10**3

def get_bit(b, i):
	return b[i >> 3] >> 7 - (i & 7) & 1
def set_bit(b, i, x):
	b[i >> 3] |= x << 7 - (bit & 7)

cnt = [[0, 0] for _ in range(8 * 21)]
for _ in range(n // connection_chunk):
	print(f"Connection {_ + 1}/{n // connection_chunk}")
	encs = []
	with process(["python3", "chall.py"]) as io:
	# with remote("chal.wwctf.com", 8005) as io:
		for _ in range(connection_chunk // chunk):
			print(f"Chunk #{_}")
			for _ in range(chunk):
				io.sendline(b"enc")
				io.sendline(b"0" * 32)
				io.sendline(b"flag")
			data = io.readlinesS(2 * chunk)
			for i in range(0, 2 * chunk, 2):
				encs.append(bytes.fromhex(data[i][2:]) + bytes.fromhex(data[i + 1][1:]))
	for enc in encs:
		for bit in range(flag_len):
				cnt[bit][
					get_bit(enc, bit) ^
					get_bit(enc, bit + 1) ^
					get_bit(enc, bit + 2) ^
					get_bit(enc, bit + 7) ^
					get_bit(enc, bit + 128)
				] += 1
	flag = [0] * (flag_len // 8)
	for bit in range(flag_len):
		x = int(cnt[bit][0] < cnt[bit][1])
		for pbit in [bit - 128, bit - 127, bit - 126, bit - 121]:
			if pbit >= 0:
				x ^= get_bit(flag, pbit)
		set_bit(flag, bit, x)
	flag = bytes(flag)
	print(f"{flag = }")
	print()
```
