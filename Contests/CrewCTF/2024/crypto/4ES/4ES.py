#!/usr/bin/env python3

from hashlib import sha256
from random import choices

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


with open('flag.txt', 'rb') as f:
    FLAG = f.read().strip()

chars = b'crew_AES*4=$!?'
L = 3

w, x, y, z = (
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
    bytes(choices(chars, k=L)),
)

k1 = sha256(w).digest()
k2 = sha256(x).digest()
k3 = sha256(y).digest()
k4 = sha256(z).digest()

print(w.decode(), x.decode(), y.decode(), z.decode())

pt = b'AES_AES_AES_AES!'
ct = AES.new(k4, AES.MODE_ECB).encrypt(
         AES.new(k3, AES.MODE_ECB).encrypt(
             AES.new(k2, AES.MODE_ECB).encrypt(
                 AES.new(k1, AES.MODE_ECB).encrypt(
                     pt
                 )
             )
         )
     )

key = sha256(w + x + y + z).digest()
enc_flag = AES.new(key, AES.MODE_ECB).encrypt(pad(FLAG, AES.block_size))

with open('output.txt', 'w') as f:
    f.write(f'pt = {pt.hex()}\nct = {ct.hex()}\nenc_flag = {enc_flag.hex()}')
