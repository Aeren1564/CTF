#!/usr/bin/env python3

from quantcrypt.kem import MLKEM_1024
from quantcrypt.cipher import KryptonKEM
from random import randint
from pathlib import *
from os import urandom
from flag import flag

kem = MLKEM_1024()
kry = KryptonKEM(MLKEM_1024)
pt = Path('/Mechanic/flag.png')
f = open('output.raw', 'wb')
m = randint(2 ** 39, 2 ** 40)
B, c = bin(m)[2:], 0
for b in B:
	if b == '1':
		pkey, skey = kem.keygen()
		ct = Path(f'/flag_{c}.enc')
		kry.encrypt(pkey, pt, ct)
		pt = ct
		c += 1
	else:
		pkey, skey = urandom(kem.param_sizes.pk_size), urandom(kem.param_sizes.sk_size)
	f.write(skey)
f.close()