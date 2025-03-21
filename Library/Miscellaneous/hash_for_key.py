def hash_for_key(secret, hash_f = __import__("hashlib").sha1):
	return hash_f(str(secret).encode()).digest()[:16]
