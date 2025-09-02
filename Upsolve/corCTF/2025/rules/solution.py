from CTF_Library import *

def f(a, b, c):
	return 1 & ~((a & c & b) | (~a & ~c & ~b) | (~a & c & ~b))

for a, b, c, d, e in itertools.product(range(2), repeat = 5):
	if c == f(f(a, b, c), f(b, c, d), f(c, d, e)):
		print(a, b, c, d, e)

obj = json.dumps([0b01110111] * 1024).replace(" ", "")

attempt = 0
while True:
	attempt += 1
	print(f"{attempt = }")
	with remote("ctfi.ng", 31126) as io:
		solve_pwn_red_PoW(io)
	# with process(["python3", "rules.py"]) as io:
		io.sendline(obj.encode())
		io.sendline(obj.encode())
		resp = io.readallS(timeout = 1).strip()
		print(resp)
		if "corctf" in resp:
			break
