from CTF_Library import *
import x25519

x = 39382357235489614581723060781553021112529911719440698176882885853963445705823
assert x == x25519.djbec.decodeint(x25519.djbec.encodeint(x))
assert 2 <= x < 2**255 - 20

while True:
	# with process(["python3", "chall.py"]) as io:
	with remote("host8.dreamhack.games", 14269) as io:
		pks = []
		for _ in range(2):
			io.readuntil(b": ")
			pks.append(bytes.fromhex(io.readlineS()))
			io.sendlineafter(b">>> ", b"y")
			io.sendlineafter(b">>> ", x25519.djbec.encodeint(x).hex().encode())
		print(io.readlines(2))
		resp = io.readlineS().strip()
		print(f"{resp = }")
		if resp == "Safety check failed. Probably MITM...":
			continue
		io.readuntil(b": ")
		enc_left = bytes.fromhex(io.readlineS().strip())
		iv_left, enc_left = enc_left[:16], enc_left[16:]
		io.readuntil(b": ")
		enc_right = bytes.fromhex(io.readlineS().strip())
		iv_right, enc_right = enc_right[:16], enc_right[16:]
		for i in range(1, 8):
			secret = x25519.scalar_mult(x25519.djbec.encodeint(i), x25519.djbec.encodeint(x))
			cipher_left = AES.new(secret, AES.MODE_CBC, iv_left)
			cipher_right = AES.new(secret, AES.MODE_CBC, iv_right)
			print(cipher_left.decrypt(enc_left))
			print(cipher_right.decrypt(enc_right))
			print()
		exit()
