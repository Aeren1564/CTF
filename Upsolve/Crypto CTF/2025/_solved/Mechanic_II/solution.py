from CTF_Library import *

charset = string.printable[:63] + '_'
tails = ["".join(tail).encode() for tail in itertools.product(charset, repeat = 4)]

def solve_PoW(head, h):
	def solve_for_rem(rem):
		for tail in tails[rem : len(tails) : os.cpu_count()]:
			if hashlib.sha3_256(head + tail).hexdigest() == h:
				return tail
	with ThreadPoolExecutor(max_workers = os.cpu_count()) as executor:
		for tail in executor.map(solve_for_rem, range(os.cpu_count())):
			if tail != None:
				return tail

for it in range(10**6):
	print(f"Iteration #{it}")
	IP = ["91.107.132.34", "91.107.252.0"][it % 1]
	with remote(IP, 11111) as io:
	# with process(["python3", "mechanic_ii.py"]) as io:
		io.readlines(4)
		io.sendline(solve_PoW(*ast.literal_eval(io.readlineS().strip().split(": ")[1])))
		io.sendline(b"d")
		io.sendline(b"0")
		io.readlines(6)
		shasec = ast.literal_eval(io.readlineS().strip().split(" = ")[1])
		secret = hashlib.sha3_256(shasec + hashlib.sha3_256(shasec + b"0").digest()).hexdigest().encode()
		io.sendline(b"s")
		io.sendline(secret)
		io.readlines(6)
		resp = io.readline()
		print(f"{resp = }")
		if b"CCTF{" in resp:
			print(resp)
			exit()
