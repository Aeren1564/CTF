from CTF_Library import *

with remote("0.0.0.0", 1337) as nc:
	print(nc.readuntilS(b"Guest: "), end = "")
	enc_guest = nc.readlineS().strip()
	print(enc_guest)
	guest = b"{'username':'guest_user','role':0}"
	iv, enc_guest = bytes.fromhex(enc_guest[ : 32]), bytes.fromhex(enc_guest[32 : ])

	def padding_oracle(iv, ciphertext):
		assert len(ciphertext) % 16 == 0 and len(iv) == 16 and len(ciphertext) > 0
		print(list(iv))
		print(list(ciphertext))
		print(nc.readuntilS(b": "))
		to_send = iv.hex() + ciphertext.hex()
		print(to_send)
		nc.sendline(to_send.encode())
		msg = nc.readn(7)
		if msg != b"Error!\n":
			print(f" Success, {msg = }")
			nc.unread(msg)
			return True
		else:
			nc.unread(msg)
			print(" " + nc.readlineS(), end = "")
			return False

	admin = pad(json.dumps({"username":"administrative_user","role":1}).encode(), 16)

	iv, enc_admin = forge_CBC_ciphertext_with_padding_oracle(admin, padding_oracle, hint = (guest[ : 16], iv, enc_guest[ : 16]), faulty = True)[0]

	print(f"{enc_admin = }")
	print(nc.readuntilS(b": "))
	to_send = iv.hex() + enc_admin.hex()
	print(f"{to_send = }")
	nc.sendline(to_send.encode())

	print(nc.readlinesS(4))
	print(nc.readuntilS(b": "))
	enc_example = nc.readlineS().strip()
	iv, enc_example = bytes.fromhex(enc_example[ : 32]), bytes.fromhex(enc_example[32 : ])
	print(f"{iv = }, {enc_example = }")

	pr = pad(b"print(flag)", 16)
	example = pad(b"print(1337)", 16)
	
	new_iv = [0] * 16
	for i in range(16):
		new_iv[i] = iv[i] ^ pr[i] ^ example[i]

	print(nc.readuntilS(b": "))
	to_send = bytes(new_iv).hex() + enc_example.hex()
	print(f"{to_send = }")
	nc.sendline(to_send.encode())
	print(nc.readlineS())
