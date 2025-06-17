from CTF_Library import *

m = b'Blue is greener than purple for sure!'
enc_m = bytes.fromhex("fe9d88f3d675d0c90d95468212b79e929efffcf281d04f0cfa6d07704118943da2af36b9f8")
enc_flag = bytes.fromhex("de9289f08d6bcb90359f4dd70e8d95829fc8ffaf90ce5d21f96e3d635f148a68e4eb32efa4")

flag = []
for x, y, z in zip(m, enc_m, enc_flag):
	flag.append(x ^ y ^ z)
print(bytes(flag))