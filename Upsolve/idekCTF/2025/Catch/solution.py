from CTF_Library import *

with remote("catch.chal.idek.team", 1337) as io:
	for _ in range(20):
		print(f"Round {_ + 1}/20")
		io.readuntil(b"Co-location: ")
		cx, cy = map(int, io.readlineS().strip()[1:-1].split(", "))
		print(f"{cx = }, {cy = }")
		io.readuntil(b"Cat's hidden mind: ")
		mind = bytes.fromhex(io.readlineS().strip())
		mat = []
		for i in range(0, 1000, 8):
			step = mind[i:i+8]
			step = [int.from_bytes(step[i:i+2], "big") for i in range(0, 8, 2)]
			mat.append(matrix(ZZ, [
				[step[0], step[1]],
				[step[2], step[3]]
			]))
		io.readuntil(b"Cat now at: ")
		dx, dy = map(int, io.readlineS().strip()[1:-1].split(", "))
		print(f"{dx = }, {dy = }")
		res = []
		def f(depth):
			global dx, dy
			print(f"{depth = }, {dx.bit_length() = }, {dy.bit_length() = }")
			if max(dx, dy).bit_length() <= 256:
				return cx, cy == dx, dy
			for i in range(len(mat)):
				cur = deepcopy(mat[i])
				mat.pop(i)
				try:
					nx, ny = cur.solve_right(vector(ZZ, [dx, dy]))
					if nx in ZZ and ny in ZZ and min(nx, dy) >= 0:
						dx, dy = int(nx), int(ny)
						res.append(cur)
						if f(depth + 1):
							return True
						res.pop(-1)
				except Exception as e:
					print(f"Error: {e}")
				mat.insert(i, cur)
			return False
		assert f(0)
		io.readuntil(b"(hex): ")
		path = b""
		for mat in reversed(res):
			for i in range(2):
				for j in range(2):
					path += int(mat[i, j]).to_bytes(2, "big")
		io.sendline(path.hex().encode())
		print(io.readlineS())
	print(io.readallS(timeout = 1))

"""
[Cat]
x, y: 256 bit int
step: len 125 list of unique 64-bit integers
"""
