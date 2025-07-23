from CTF_Library import *

from quantcrypt.kem import MLKEM_1024
from quantcrypt.cipher import KryptonKEM
from pathlib import *

kem = MLKEM_1024()
kry = KryptonKEM(MLKEM_1024)
skey_len = kem.param_sizes.sk_size

with open("output.raw", "rb") as file:
	skeys = file.read()

ct = Path("./flag_22.enc")
for c in reversed(range(-1, 22)):
	print(f"{c = }")
	while True:
		try:
			skey, skeys = skeys[-skey_len:], skeys[:-skey_len]
			pt = Path(f"./flag_{c}.enc") if c >= 0 else Path(f"./flag.png")
			kry.decrypt_to_file(skey, ct, pt)
			ct = pt
			print(f"Ok")
			break
		except:
			print(f"Pass")
			pass
