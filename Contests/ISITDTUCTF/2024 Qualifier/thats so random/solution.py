from CTF_Library import *
import resource
resource.setrlimit(resource.RLIMIT_STACK, (2**29,-1))
sys.setrecursionlimit(10**6)

windows = [20 * i for i in range(1, 11)]

def statistics():
	pool = [0, 1, 1, 1, 1]
	rep, n = 500, 2000
	min_adj = [ 10**9] * (2 + len(windows))
	max_adj = [-10**9] * (2 + len(windows))
	for _ in range(rep):
		a = [random.choice(pool) for _ in range(n)]
		l = 0
		while l < n:
			r = l + 1
			while r < n and a[l] == a[r]:
				r += 1
			min_adj[a[l]] = min(min_adj[a[l]], r - l)
			max_adj[a[l]] = max(max_adj[a[l]], r - l)
			l = r
		for t, w in enumerate(windows):
			cnt = 0
			for i in range(w - 1):
				cnt += a[i]
			for l in range(0, n - w + 1):
				r = l + w
				cnt += a[l + w - 1]
				min_adj[t + 2] = min(min_adj[t + 2], w - cnt)
				max_adj[t + 2] = max(max_adj[t + 2], w - cnt)
				cnt -= a[l]
	print(f"{min_adj = }")
	print(f"{max_adj = }")
	print(f"                        min,    max")
	print(f"consec zero           : {str(min_adj[0]).zfill(3)},    {str(max_adj[0]).zfill(3)}")
	print(f"consec one            : {str(min_adj[1]).zfill(3)},    {str(max_adj[1]).zfill(3)}")
	for t, w in enumerate(windows):
		print(f"zero cnt on window {str(w).zfill(3)}: {str(min_adj[2 + t]).zfill(3)},    {str(max_adj[2 + t]).zfill(3)}")
	print(f"=================================================")
	print()

statistics()

min_adj = [1, 1, 0, 0, 1, 2, 4, 8, 10, 13, 14, 16]
max_adj = [9, 59, 15, 22, 29, 38, 47, 53, 57, 60, 62, 66]

upto = int(0x13371337*1.337)
width = upto.bit_length()
with open("output.txt") as f:
	output = literal_eval(f.read())
assert width <= 32

print(f"{upto = }")
print(f"{width = }")
print(f"{len(output) = }")

W, N, n = 32, 624, 3000
twister = symbolic_mersenne_twister(init_index = N)
equations = [list(reversed(twister.getrandbits(width))) for _ in range(n)]
solver = linear_equation_solver_GF2(n = W * N)
for i in range(W):
	assert solver.add_equation_if_consistent(2**i, 1 if i == W - 1 else 0)

one_pos = [-1]
solvers = [deepcopy(solver)]

def valid():
	for t, w in enumerate(windows):
		if one_pos[-1] < w - 1:
			break
		cnt = w
		for x in reversed(one_pos[1:]):
			if one_pos[-1] - x >= w:
				break
			cnt -= 1
		if not (min_adj[t + 2] <= cnt <= max_adj[t + 2]):
			return False
	return True

def apply_output(solver, eqs, x):
	for i in range(width):
		if not solver.add_equation_if_consistent(eqs[i], x >> i & 1):
			return False
	return True

def format_one_pos():
	formatted = ""
	for i in one_pos[1:]:
		while len(formatted) < i:
			formatted += '0'
		formatted += '1'
	return formatted

from hashlib import sha512
obj = b"ISITDTU{"
robj = bytes(list(reversed(obj)))

print(f"{obj = }")
print(f"{robj = }")

def check_assignment(assignment : int):
	state = [assignment >> W * i & 0xFFFFFFFF for i in range(N)] + [N]
	recovered = bytes([x >> 8 * i & 0xFF for x in reversed(mersenne_twister_breaker().recover_seed_array_from_state(state, True)) for i in range(3, -1, -1)])
	print(f"{recovered = }")
	return (obj in recovered) or (robj in recovered)

def f():
	print(f"one_pos: {format_one_pos()}")
	print(f"step: {len(one_pos) - 1}")
	if len(solvers[-1].equations_and_outputs) == solvers[-1].n:
		print(f"Equation saturated")
		assignment, basis = solvers[-1].solve()
		assert len(basis) == 0
		if check_assignment(assignment):
			exit(0)
		return
	start = one_pos[-1] + 1
	end = min(len(equations), start + max_adj[0])
	for i in range(start, end):
		one_pos.append(i)
		solvers.append(deepcopy(solvers[-1]))
		if valid() and apply_output(solvers[-1], equations[i], output[len(one_pos) - 2]):
			f()
		one_pos.pop()
		solvers.pop()
f()