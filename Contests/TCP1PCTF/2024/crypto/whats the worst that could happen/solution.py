from CTF_Library import *

with remote("ctf.tcp1p.team", 19328) as io:
	enc_admin_id = bytes.fromhex(io.readlineS().strip().split(": ")[1])

	def encrypt_send(m: bytes):
		io.sendline(b"1")
		io.sendline(m)

	def encrypt_read():
		io.readuntilS(b"Encrypted: ")
		return bytes.fromhex(io.readlineS().strip())

	def request_flag(admin_id: bytes):
		io.sendlineafter(b">> ", b"2")
		io.sendlineafter(b"Enter ID: ", admin_id)
		print(io.readallS(timeout = 1))

	admin_id = [-1] * 16

	for a, b in itertools.product(range(16), range(16)):
		for c, d in itertools.product(range(16), range(16)):
			encrypt_send("".join([hex(z)[2 :] for z in [a, b, c, d]]).encode() * 4)
		for c, d in itertools.product(range(16), range(16)):
			m = [a, b, c, d]
			enc_m = encrypt_read()
			for i in range(0, 16, 4):
				if enc_admin_id[i : i + 4] == enc_m[i : i + 4]:
					for j in range(4):
						admin_id[i + j] = ord(hex(m[j])[2: ])

	request_flag(bytes(admin_id))
