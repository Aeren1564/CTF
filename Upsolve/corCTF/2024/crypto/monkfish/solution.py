import ast
from pwn import *

while True:
	nc = remote('be.ax', 31105)
	print(nc.recvuntil(b'I caught a monkfish in the sea!'), nc.recvline())
	
	nc.recvuntil(b'm0 = ')
	m0 = ast.literal_eval(nc.recvline().decode().strip())
	nc.recvuntil(b'm1 = ')
	m1 = ast.literal_eval(nc.recvline().decode().strip())
	nc.recvuntil(b'm2 = ')
	m2 = ast.literal_eval(nc.recvline().decode().strip())
	print(f"{m0 = }")
	print(f"{m1 = }")
	print(f"{m2 = }")

	print(nc.recvuntil(b'Can you catch a monkfish?'), nc.recvline())
	print(nc.recvline())
	print(nc.recvline())

	m0 = repr([4 * x % 5 for x in m0]).encode()
	m1 = repr([2 * x % 5 for x in m1]).encode()
	m2 = repr([2 * x % 5 for x in m2]).encode()

	nc.recvuntil(b'm0 = ')
	nc.sendline(m0)
	nc.recvuntil(b'm1 = ')
	nc.sendline(m1)
	nc.recvuntil(b'm2 = ')
	nc.sendline(m2)
	print(f"sending {m0 = }")
	print(f"sending {m1 = }")
	print(f"sending {m2 = }")

	resp = nc.recvline()
	
	if resp[: 9] != b'Traceback':
		print(resp)
		break
	else:
		print("FAILED :(")

	nc.close()