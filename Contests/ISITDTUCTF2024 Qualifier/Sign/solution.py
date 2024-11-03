from CTF_Library import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Util import asn1
from Crypto.Util.number import size

def genkey(e=11):
	while True:
		p = getPrime(1024)
		q = getPrime(1024)
		if GCD(p-1, e) == 1 and GCD(q-1, e) == 1:
			break
	n = p*q
	d = pow(e, -1, (p-1)*(q-1))
	return RSA.construct((n, e, d))

key = genkey()

for _ in range(10):
	m = os.urandom(256)
	h = SHA256.new(m)
	s = PKCS1_v1_5.new(key).sign(h)
	k = (size(key.n) + 7) // 8

	print(f"{m = }")
	print(f"{s = }")
	print(f"{k = }")
	digestAlgo = asn1.DerSequence([ asn1.DerObjectId(h.oid).encode() ])
	digestAlgo.append(asn1.DerNull().encode())
	digest = asn1.DerOctetString(h.digest())
	digestInfo  = asn1.DerSequence([ digestAlgo.encode(), digest.encode() ]).encode()
	print(f"{len(digestAlgo.encode()) = }")
	print(f"{digestAlgo.encode() = }")
	print(f"{len(digest.encode()) = }")
	print(f"{digest.encode() = }")
	print(f"{len(digestInfo) = }")
	print(f"{digestInfo = }")
	print()

# with process(["python3", "chall.py"]) as io:
# 	def random_sig():
# 		io.readuntil(b"> ")
# 		io.sendline(b"1")
# 		return unhex(io.readlineS().strip().split("= ")[1])

# 	def flag_sig():
# 		io.readuntil(b"> ")
# 		io.sendline(b"2")
# 		return unhex(io.readlineS().strip().split("= ")[1])

# 	for i in range(100):
# 		