#!/usr/bin/env python3

import sys
from Crypto.PublicKey import ECC
from Crypto.Signature import eddsa
from flag import flag

def die(*args):
	pr(*args)
	quit()

def pr(*args):
	s = " ".join(map(str, args))
	sys.stdout.write(s + "\n")
	sys.stdout.flush()

def sc():
	return sys.stdin.buffer.readline()

def init_data():
	global alice_data

	alice_data = []
	alice_key = ECC.generate(curve = "ed25519")
	signer = eddsa.new(alice_key, "rfc8032")
	public_key = alice_key.public_key().export_key(format="raw")
	for msg in [
		b"Alice cracks codes in her sleep.",
		b"Alice never leaves a cipher unsolved.",
		b"No flag for those who give up too soon, says Alice.",
		b"Alice never gives up; that's why she always gets the flag.",
		b"Alice loves solving ciphers, especially when they're tricky.",
	]:
		signature = signer.sign(msg)
		alice_data.append((public_key, signature[:32], signature[32:], msg))

def erase():
	global alice_data
	for i, row in enumerate(alice_data):
		alice_data[i] = (b"",) * i + row[i:]

def alice_check():
	global alice_data
	for public_key, r, s, msg in alice_data:
		if min(map(len, [public_key, r, s, msg])) == 0:
			return False
		public_key = eddsa.import_public_key(encoded=public_key)
		if public_key.pointQ.x * public_key.pointQ.y == 0:
			return False
		verifier = eddsa.new(public_key, "rfc8032")
		try:
			verifier.verify(msg, r + s)
		except ValueError:
			print("Wrong sign")
			return False
	return True

def main():
	border = "┃"
	pr("┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓")
	pr(border, "I accidentally triggered a function that erased part of Alice's data. ", border)
	pr(border, "Can you help me recover it before she finds out?                      ", border)
	pr("┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛")
	
	global alice_data

	init_data()
	erase()

	while True:
		pr(
			f"{border} Options: \n{border}\t[G]et data \n{border}\t[U]pdate data \n{border}\t[A]lice check \n{border}\t[Q]uit"
		)
		ans = sc().decode().strip().lower()
		if ans == "g":
			for row_inx, row_val in enumerate(alice_data):
				pr(border, row_inx, ":", ", ".join(map(bytes.hex, row_val)))
		elif ans == "u":
			pr(border, "row_inx, public_key, r, s, msg:")
			_new_data = sc().decode()
			try:
				_new_data = _new_data.split(",")
				row_inx = int(_new_data[0])
				public_key, r, s, msg = map(bytes.fromhex, _new_data[1:])
			except:
				die(border, "Bad input! Quitting...")

			new_row = [public_key, r, s, msg]
			if 0 <= row_inx < len(alice_data) and all(
				len(old_val) == 0 or new_val == old_val
				for old_val, new_val in zip(alice_data[row_inx], new_row)
			):
				alice_data[row_inx] = new_row
			else:
				die(border, "Bad input values! Quitting...")
		elif ans == "a":
			if alice_check():
				die(border, f"Hey Alice, everything seems fine here! Here's the {flag: }!")
			else:
				die(border,	"Uh-oh, Alice! Looks like the data went on vacation without telling anyone.")
		elif ans == "q":
			die(border, "Quitting...")
		else:
			die(border, "Bye...")

if __name__ == "__main__":
	main()