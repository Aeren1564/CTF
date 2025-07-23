from CTF_Library import *
import cuso

u, v, w, x, y, z = var("u, v, w, x, y, z")

with open("output.txt") as file:
	p = int(file.readline().strip().split(" = ")[1])
	relations = []
	for _ in range(6):
		relations.append(eval(file.readline().strip().split(" = ")[1]) == 0)

moduli = [p] * 6
bounds = {
	u: (0, 2**112),
	v: (0, 2**112),
	w: (0, 2**112),
	x: (0, 2**112),
	y: (0, 2**112),
	z: (0, 2**112),
}
roots = cuso.find_small_roots(
	relations,
	bounds,
	modulus = moduli
)
flag = b"CCTF{"
for x in [u, v, w, x, y, z]:
	flag += roots[0][x].to_bytes(14)
flag += b"}"
print(flag)
