from CTF_Library import *
from chall import dna_rules, xor_matrices, scramble_matrix

with remote("ctf.tcp1p.team", 1975) as io:
	io.readline()
	enc_flag = np.array(list(io.readlineS().strip())).reshape(-1, 16)

	def get_enc(mat):
		io.sendlineafter(b")", "".join("".join(row) for row in mat).encode())
		io.readline()
		return np.array(list(io.readlineS().strip())).reshape(-1, 16)

	def unscramble_matrix(mat, lx, ly):
		assert mat.shape[0] == len(lx) and mat.shape[1] == len(ly)
		revlx, revly = [0] * len(lx), [0] * len(ly)
		for i in range(len(lx)):
			revlx[lx[i]] = i
		for j in range(len(ly)):
			revly[ly[j]] = j
		return scramble_matrix(mat, np.array(revlx), np.array(revly))[:]

	def dna_decode_matrix(dna_matrix, rule_number):
		rule = dna_rules[rule_number]
		rev_rule = {v: k for k, v in rule.items()}
		decoded_rows = []
		for row in dna_matrix:
			bit_pairs = [rev_rule.get(base, '00') for base in row]
			num_bits = ''.join(bit_pairs)
			num_bytes = len(num_bits) // 8
			decoded_row = [int(num_bits[i*8:(i+1)*8], 2) for i in range(num_bytes)]
			decoded_rows.append(decoded_row)
		return np.array(decoded_rows, dtype=np.uint8)

	keymat = get_enc(np.array([['G'] * 16 for i in range(16)]))

	lx, ly = [-1] * 16, [-1] * 16
	mat = xor_matrices(keymat, get_enc(np.array([['A' if j < i else 'C' for j in range(16)] for i in range(16)])), 3)
	for i in range(16):
		lx[i] = sum(1 if c == 'A' else 0 for c in mat[i, :])
	for j in range(16):
		ly[j] = sum(1 if c == 'C' else 0 for c in mat[:, j]) - 1

	mat = xor_matrices(keymat, enc_flag, 3)
	flag = bytes(list(x for row in dna_decode_matrix(unscramble_matrix(mat, lx, ly), 3) for x in row))
	print(flag)

