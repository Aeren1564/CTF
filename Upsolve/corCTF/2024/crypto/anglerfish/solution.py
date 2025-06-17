import ast
from pwn import *
from hashlib import sha256
from random import SystemRandom

rng = SystemRandom()

while True:
	nc = remote('be.ax', 31106)
	print(nc.recvuntil(b'I caught an anglerfish in the sea!'), nc.recvline())

	pi = []
	for i in range(64):
		nc.recvuntil(b'm0 = ')
		m0 = ast.literal_eval(nc.recvline().decode().strip())
		nc.recvuntil(b'm1 = ')
		m1 = ast.literal_eval(nc.recvline().decode().strip())
		nc.recvuntil(b'm2 = ')
		m2 = ast.literal_eval(nc.recvline().decode().strip())
		pi.append((m0, m1, m2))

	print(nc.recvuntil(b'Can you catch an anglerfish?'), nc.recvline())
	print(nc.recvline())
	nc.recvuntil(b'v = ')
	v = ast.literal_eval(nc.recvline().decode().strip())
	print(f"{v = }")

	fake = []
	def try_appending(m0, m1, m2):
		if m0 not in [x[0] for x in fake] and m0 not in [x[0] for x in pi]:
			if m1 not in [x[1] for x in fake] and m1 not in [x[1] for x in pi]:
				if m2 not in [x[2] for x in fake] and m2 not in [x[2] for x in pi]:
					fake.append((m0, m1, m2))

	for i in range(64):
		m0, m1, m2 = pi[i]
		a = sha256(bytes(m0 + v + m2)).digest()[0] % 5
		# no swap
		for coef in [2, 3]:
			m0_next = [coef * coef * x % 5 for x in m0]
			m1_next = [       coef * x % 5 for x in m1]
			if a == 0:
				while True:
					# veri can be anything for m2
					m2_next = [rng.randint(0, 4) for _ in range(100)]
					a_next  = sha256(bytes(m0_next + v + m2_next)).digest()[0] % 5
					if a_next == 0:
						try_appending(m0_next, m1_next, m2_next)
						break
			else:
				m2_next = [coef * x % 5 for x in m2]
				a_next  = sha256(bytes(m0_next + v + m2_next)).digest()[0] % 5
				if a * coef % 5 == a_next:
					try_appending(m0_next, m1_next, m2_next)
		# swap m0 and m2
		for coef in [2, 3, 4]:
			m0_next = [-coef * coef * a * x % 5 for x in m2]
			m1_next = [coef * x % 5 for x in m1]
			a_next = a * coef % 5
			if a_next != 0:
				m2_next = [x * coef * coef * pow(-a_next % 5, -1, 5) % 5 for x in m0]
				if sha256(bytes(m0_next + v + m2_next)).digest()[0] % 5 == a_next:
					try_appending(m0_next, m1_next, m2_next)

	print(f"{len(fake) = }")

	if len(fake) < 64:
		print("Failed :(")
		nc.close()
		continue

	print("Success!")

	fake = fake[0 : 64]

	for i, (m0, m1, m2) in enumerate(fake):
		m0 = repr(m0).encode()
		m1 = repr(m1).encode()
		m2 = repr(m2).encode()
		nc.recvuntil(b'm0 = ')
		nc.sendline(m0)
		nc.recvuntil(b'm1 = ')
		nc.sendline(m1)
		nc.recvuntil(b'm2 = ')
		nc.sendline(m2)
		print(f"{i = }")
		print(f"sending {m0 = }")
		print(f"sending {m1 = }")
		print(f"sending {m2 = }")

	resp = nc.recvline()
		
	print(resp)

	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())
	print(nc.recvline())

	assert resp[: 9] != b'Traceback'

	break