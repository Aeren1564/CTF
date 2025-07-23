from CTF_Library import *
from sh_rsa import *

mpmath.mp.dps = 1000

e = 0x10001
block_cnt = 512 - 64
shift = 2**200

with process(["python3", "sh_rsa.py"]) as io:
	n = int(io.readlineS().strip().split(" = ")[1])
	io.readline()
	goal = H(n, b"challenge")
	assert goal[0]
	goal = bytes_to_long(goal) 
	goal_lb = mpmath.mp.log(goal * 256**block_cnt)
	goal_ub = mpmath.mp.log((goal + 1) * 256**block_cnt - 1)

	data = []
	for i in range(92):
		m = long_to_bytes(i)
		s = int(io.readlineS().strip().split(" ")[1], 16)
		if verify(n, e, m, s):
			h = bytes_to_long(H(n, m))
			data.append([s, mpmath.mp.log(h)])

	samples = random.sample(range(len(data)), 48)
	solver = inequality_solver_with_SVP([0] * len(samples), [10] * len(samples))
	solver.add_inequality(
		[int(data[index][1] * shift) for index in samples],
		int(goal_lb * shift),
		int(goal_ub * shift)
	)

	for assignment, _ in solver.solve(10**9):
		s = 1
		for i, index in enumerate(samples):
			s = s * pow(data[index][0], assignment[i], n) % n
		assert verify(n, e, b'challenge', s)
		io.sendline(hex(s).encode())
		print(io.readallS(timeout = 1))
		exit()
