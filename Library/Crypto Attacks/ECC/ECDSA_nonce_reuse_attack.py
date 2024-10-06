# n: order of generator
# h1, h1: message hashes (possibly truncated)
# r0, s0, r1, s1: signatures
@staticmethod
def ECDSA_nonce_reuse_attack(n : int, h0 : int, r0 : int, s0 : int, h1 : int, r1 : int, s1 : int):
	nonce = (h0 - h1) * pow(s0 - s1, -1, n) % n
	private_key = (s0 * nonce - h0) * pow(r0, -1, n) % n
	assert s1 == pow(nonce, -1, n) * (h1 + r1 * private_key) % n
	return private_key, nonce
