from secret import flag
from Crypto.Util.number import getPrime, bytes_to_long

assert len(flag) == 64
m1 = bytes_to_long(flag[:32].encode())
m2 = bytes_to_long(flag[32:].encode())

p = getPrime(256)
def release(m):
	print(hex((m * pow(2, m, p)) % p)[2:].rjust(64, '0'))

print(hex(p)[2:])
release(m1)
release(m2)
release(m2-m1)
release(m2+m1)
