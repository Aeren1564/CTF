from CTF_Library import *
from public_key import pk

F = GF(127)
n = 48
v = 120
l = 6

def recover_pk():
	def expand_column(vec):
		M = []
		for k in range(l):
			M.append([(x * 2**k) % 127 for x in vec])
		return M
	_Pk = []
	for p in pk:
		MT = []
		for c in p:
			cs = expand_column(c)
			MT += cs
		M = [[None for _ in range(n+v)] for _ in range(n+v)]
		for i in range(n+v):
			for j in range(n+v):
				M[i][j] = MT[j][i]
		_Pk.append(matrix(F, M))
	return _Pk
pk = recover_pk()
print(f"{len(pk) = }")

init_vector = vector(F, [random.randrange(127) for _ in range(n + v)])
kernel_vectors = [vector(F, [(-2 if i == j else 1 if i + 1 == j else 0) for j in range(n + v)]) for i in range(n + v) if i % l != l - 1]
for p in pk:
	for kv in kernel_vectors:
		assert p * kv == zero_vector(F, n + v)
coef_iv = vector(F, [(matrix(init_vector) * p * init_vector)[0] for p in pk])
coef_kv = [vector(F, [(matrix(kv) * p * init_vector)[0] for p in pk]) for kv in kernel_vectors]

with remote("challs.umdctf.io", 31302) as io:
	def solve_pow():
		print(f"PoW start")
		first_line = io.recvline().decode()
		script_line = first_line + io.recvline().decode()
		cmd_arg     = script_line.split()[-1]
		pow_cmd     = ["bash", "-c", f"curl -sSfL https://pwn.red/pow | sh -s {cmd_arg}"]
		pow_sol     = subprocess.check_output(pow_cmd).strip()
		io.readuntilS(b"solution: ")
		io.sendline(pow_sol)  
		print(f"PoW end")
		return
	solve_pow()
	io.readuntil(b"The message to sign is ")
	target = vector(F, literal_eval(io.readlineS().strip())) - coef_iv
	print(f"{target = }")
	coef = matrix(F, coef_kv).solve_left(target)
	res = init_vector
	for i, v in enumerate(kernel_vectors):
		res += coef[i] * v
	io.sendline(str(res)[1:-1].encode())
	print(io.readallS(timeout = 1))
