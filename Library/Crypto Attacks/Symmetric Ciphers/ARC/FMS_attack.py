# https://en.wikipedia.org/wiki/Fluhrer,_Mantin_and_Shamir_attack
# get_stream(iv): returns the the cipher stream when concatenating iv at the beginning of the key
import string
def FMS_attack(key_len : int, get_stream, key_prefix : bytes = b"", valid_characters = string.ascii_letters + string.digits + "_{}!?"):
	from concurrent.futures import ThreadPoolExecutor
	import os
	mod = 256
	assert 0 < key_len <= mod - 3 and len(key_prefix) <= key_len
	if isinstance(valid_characters, str):
		valid_characters = list(map(ord, valid_characters))
	elif isinstance(valid_characters, bytes):
		valid_characters = list(valid_characters)
	assert isinstance(valid_characters, list)
	for c in valid_characters:
		assert isinstance(c, int) and 0 <= c < mod
	key = list(key_prefix)
	for index in range(len(key_prefix), key_len):
		def solve_for_remainder(rem):
			ret = []
			for x in range(rem, mod, os.cpu_count()):
				iv = [index + 3, mod - 1, x]
				first_byte = get_stream(bytes(iv))[0]
				assert isinstance(first_byte, int) and 0 <= first_byte < mod
				S, j = list(range(mod)), 0
				for i, y in enumerate(list(iv) + key):
					j = (j + S[i] + y) % mod
					S[i], S[j] = S[j], S[i]
				ret.append((first_byte - j - S[index + 3]) % mod)
			return ret
		cnt = [0] * mod
		with ThreadPoolExecutor(max_workers = os.cpu_count()) as executor:
			for ret in executor.map(solve_for_remainder, range(os.cpu_count())):
				for x in ret:
					cnt[x] += 1
		key.append(max(valid_characters, key = lambda c: cnt[c]))
		print(f"[INFO] <FMS_attack> key[: {index + 1}] = {bytes(key)}")
	return bytes(key)
