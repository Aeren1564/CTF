Our goal is to make `last_comm` filled with the same value, so that after inverse FFT, it will have degree $\le 1$. I will present a solution which makes `last_comm` all zeroes.

We can represent our payload as a sequence of arrays $L_0, \cdots, L_6$ representing the leaf values in the Merkle trees. In particular, $L_i$ will be an array of length $256 \times 2^{6-i}$, and $L_6$ will be equal to `last_comm`.

### Observation 1
- Indices with different remainder modulo $256$ does not affect each other during verification.

We'll now group every index with remainder $r$ modulo $256$, for each remainders $0 \le r < 256$.

Let's say on a round, an index went through a **normal transition** if it will pass the verifier check if the index was selected for query in that round. Otherwise, it went through an **abnormal transition**. In my solution, all abnormal transitions will set the next value to $0$.

### Observation 2
- If for some $0 \le i \le 6$ and $0 \le r < 256$, every value in group $r$ in $L_i$ were 0, for all $i < j \le 6$ every value in group $r$ in $L_j$ is $0$ as well, assuming all such values went through a normal transition.

For each group, we want it to go through an abnormal transition in a single round, and through a normal transition in other $5$ rounds.

Let $k_i$ be the proportion of groups which will go through an abnormal transition during the $i$-th round. In particular, $k_0 + \cdots + k_5 = 1$.

```
              <----k0----> <----k1----> <----k2----> <----k3----> <----k4----> <----k5---->

Groups in L0  [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ]
                    |            |            |            |            |            |
Round 0         Abnormal      Normal       Normal       Normal       Normal       Normal
                    v            v            v            v            v            v
Groups in L1  [   Zero   ] [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ]
                    |            |            |            |            |            |
Round 1          Normal      Abnormal      Normal       Normal       Normal       Normal
                    v            v            v            v            v            v
Groups in L2  [   Zero   ] [   Zero   ] [ Non-zero ] [ Non-zero ] [ Non-zero ] [ Non-zero ]
                    |            |            |            |            |            |
Round 2          Normal       Normal      Abnormal      Normal       Normal       Normal
                    v            v            v            v            v            v
Groups in L3  [   Zero   ] [   Zero   ] [   Zero   ] [ Non-zero ] [ Non-zero ] [ Non-zero ]
                    |            |            |            |            |            |
Round 3          Normal       Normal       Normal      Abnormal      Normal       Normal
                    v            v            v            v            v            v
Groups in L4  [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ] [ Non-zero ] [ Non-zero ]
                    |            |            |            |            |            |
Round 4          Normal       Normal       Normal       Normal      Abnormal      Normal
                    v            v            v            v            v            v
Groups in L5  [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ] [ Non-zero ]
                    |            |            |            |            |            |
Round 5          Normal       Normal       Normal       Normal       Normal      Abnormal
                    v            v            v            v            v            v
Groups in L6  [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ] [   Zero   ]
```

The verification will fail if and only if one of the query lands on an index going through an abnormal transition. The maximum probability of success is

$$
\begin{align*}
&\prod_{i=0}^5 (1-k_i)^{8} \\
&\le \left( \frac{\sum_{i=0}^5 (1-k_i)}6 \right) ^{48} \\
&= \left( \frac56 \right) ^{48} \\
&\simeq 0.0001582341
\end{align*}
$$

The maximum probability can be reached by setting $k_0 = \cdots = k_5 = \frac16$, and we're expected to pass the verification in about 6320 tries on average.

```python
from math import log2, ceil
from hashlib import sha256
import json
from pwn import *
import gzip
import io
import base64

from ZKP import ZKP
from merkletree import MerkleTree
from fft import fft
from Verifier import Verifier
from compression import decompress

max_output_size = 10 * 1024 * 1024

def compress(data, max_output_size=max_output_size):
	buf = io.BytesIO()
	with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
		f.write(data)
	return base64.b64encode(buf.getvalue())

p = 21888242871839275222246405745257275088548364400416034343698204186575808495617
ω = 19103219067921713944291392827692070036145651957329286315305642004821462161904
k = 14
ω = pow(ω, 2**(28-k), p)
assert pow(ω, 2**k, p) == 1 and pow(ω, 2**(k - 1), p) != 1
expansion_factor = 256
s = 8
domain_length = 2**k
nr = ceil(log2(domain_length // expansion_factor)) # 6
domain = [pow(ω, i, p) for i in range(domain_length)]

def compute_next(i, w, c, ay, by):
	ax = pow(w, i, p)
	bx = pow(w, i + dl // 2, p)
	temp = (by - ay) * pow(bx - ax, -1, p) % p
	b = (ay - temp * ax) % p
	cy = (temp * c + b) % p
	return cy

block = expansion_factor // nr
split = [block * i for i in range(nr)] + [expansion_factor]
fail_cnt = [0] * nr
# 6566472861551782566673921723577182526564509320124810303109461255972742549383
for first_value in range(p):
	print(f"{first_value = }")
	evals = [fft([domain_length + 1337 + i for i in range(domain_length)], ω, p)]
	roots = [MerkleTree(evals[-1]).get_root()]
	w = ω
	zkp = ZKP()
	challs = []
	for r in range(nr):
		dl = domain_length >> r
		zkp.transcript.put(roots[-1])
		challs.append(zkp.transcript.get_challenge())
		evals.append([compute_next(i, w, challs[-1], evals[-1][i], evals[-1][i + dl // 2]) for i in range(dl // 2)])
		# Assume indices are NOT picked from [split[r], split[r + 1])
		# For round 0, assume indices are not split[1] as well
		for i in range(dl // 2):
			if split[r] <= i % expansion_factor < split[r + 1]:
				evals[-1][i] = 0
		if r == 0:
			evals[-1][split[1]] = first_value
		roots.append(MerkleTree(evals[-1]).get_root())
		w = pow(w, 2, p)
	last_comm = evals[-1][:]
	assert last_comm == [0] * expansion_factor
	zkp.transcript.put(last_comm)

	queries = [[] for _ in range(nr)]
	for r in range(nr):
		dl = domain_length >> r
		indices = zkp.indices(dl, s)
		lowerbound = split[r]
		upperbound = split[r + 1] + int(r == 0)
		if not all(not lowerbound <= i % expansion_factor < upperbound for i in indices):
			fail_cnt[r] += 1
			print(f"Failed on {r}")
			print(f"{indices = }")
			print(f"{[i % expansion_factor for i in indices] = }")
			print(f"{fail_cnt = }")
			print()
			break
		chall = challs[r]
		for idx1 in indices:
			idx2 = (idx1 + dl // 2) % dl
			idx3 = idx1 % (dl // 2)
			qs = [None] * 3
			qs[0] = [evals[r][idx1], MerkleTree(evals[r]).get_proof(idx1)]
			qs[1] = [evals[r][idx2], MerkleTree(evals[r]).get_proof(idx2)]
			qs[2] = [evals[r + 1][idx3], MerkleTree(evals[r + 1]).get_proof(idx3)]
			queries[r].append(qs)
	else:
		verifier = Verifier()
		assert verifier.verify(last_comm, roots, queries, 0)
		with process(["python3", "server.py"]) as server:
			server.sendlineafter(b": ", compress(json.dumps({"last_comm": last_comm, "roots": roots, "queries": queries}).encode()))
			print(server.readallS(timeout = 1))
		break
```