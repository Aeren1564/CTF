from CTF_Library import *
from chall import dna_encode_matrix, dna_decode_matrix, scramble_matrix, xor_matrices
from PIL import Image

with remote("ctf.tcp1p.team", 1985) as io:
	io.readline()

	def read_dna_encoded_matrix():
		return dna_encode_matrix(np.array([list(map(int, s.split(','))) for s in io.readlineS().strip().split(";")], dtype = np.uint8), 4)[:]

	def send_dna_encoded_matrix(mat):
		io.sendline(";".join(",".join(map(str, row)) for row in dna_decode_matrix(mat, 3)).encode())

	def send_then_read_dna_encoded_matrix(mat):
		io.readuntil(b": ")
		send_dna_encoded_matrix(mat)
		io.readline()
		return read_dna_encoded_matrix()[:]

	def unscramble_matrix(mat, lx, ly):
		assert mat.shape[0] == len(lx) and mat.shape[1] == len(ly)
		revlx, revly = [0] * len(lx), [0] * len(ly)
		for i in range(len(lx)):
			revlx[lx[i]] = i
		for j in range(len(ly)):
			revly[ly[j]] = j
		return scramble_matrix(mat, np.array(revlx), np.array(revly))[:]

	enc_P = read_dna_encoded_matrix()
	nrow_P, ncol_P = enc_P.shape

	keymat = send_then_read_dna_encoded_matrix(np.array([['G' for j in range(ncol_P)] for i in range(nrow_P)]))

	lx, ly = np.array([-1] * nrow_P), np.array([-1] * ncol_P)
	for jl in range(0, ncol_P, nrow_P - 1):
		mat = xor_matrices(keymat, send_then_read_dna_encoded_matrix(np.array([['A' if j - i >= jl else 'C' for j in range(ncol_P)] for i in range(nrow_P)])), 3)
		for j in range(ncol_P):
			cnt = sum(1 if c == 'A' else 0 for c in mat[:, j])
			if 0 < cnt < nrow_P:
				ly[j] = jl + cnt - 1
		if jl == 0:
			for i in range(nrow_P):
				lx[i] = sum(1 if c == 'C' else 0 for c in mat[i, :])

	io.readuntilS(b"Prove it that now you know, what is the Plaintext Challenge? ")
	send_dna_encoded_matrix(unscramble_matrix(xor_matrices(keymat, enc_P, 3), lx, ly))
	io.readlineS()

	flag = dna_decode_matrix(unscramble_matrix(xor_matrices(keymat, read_dna_encoded_matrix(), 3), lx, ly), 3)
	Image.fromarray(flag).save('flag.png')
