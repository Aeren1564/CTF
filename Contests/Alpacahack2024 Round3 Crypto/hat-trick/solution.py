from CTF_Library import *

while True:
	try:
		with process(["python3", "server.py"]) as io:
			param = json.loads(io.readlineS().split("params: ")[1])
			p = [param[i]["p"] for i in range(3)]
			base = [param[i]["base"] for i in range(3)]
			n = 54
			for _ in range(3):
				target = ast.literal_eval(io.readlineS().split("target: ")[1])
				solver = inequality_solver_with_SVP([ord('a')] * n, [ord('z')] * n)
				for t in range(3):
					solver.add_equality([base[t]**i for i in range(n)], target[t], p[t])
				io.sendlineafter(b"> ", "".join([chr(c) for c in solver.solve()[0][0]]).encode())

			print(io.readallS(timeout = 1))
			break
	except Exception as e:
		print(f"{e = }")
