from CTF_Library import *

dim = 16
e = 65537

with open("output.txt", "r") as file:
	c = vector(ZZ, ast.literal_eval(file.readline().split(" = ")[1]))
	ct = ast.literal_eval(file.readline().split(" = ")[1])

ker_c = orthogonal_basis([c])[:dim**2 - dim - 1]
candidates = orthogonal_basis(ker_c)
I = candidates[0]
J = candidates[1]
if min(I) < 0:
	I = -I
if min(J) < 0:
	J = -J

t = -min(J)
while True:
	M = J + t * I
	t += 1
	if 0 <= min(M) and max(M) < 256:
		key = bytes(M.list())
		flag = AES.new(key[:32], AES.MODE_CTR, nonce = key[-8:]).decrypt(ct)
		if flag.isascii():
			print(flag)
			break
