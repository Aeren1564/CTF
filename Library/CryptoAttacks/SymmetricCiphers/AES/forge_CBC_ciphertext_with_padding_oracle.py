# Hint is a tuple of (message, iv, ciphertext) which are bytes of length 16
# padding_oracle(iv, ciphertext) checks whether the text is padded
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns a tuple of iv and ciphertext if not faulty, otherwise all possible such tuples
def forge_CBC_ciphertext_with_padding_oracle(text : bytes, padding_oracle, hint = None, faulty = False):
	n, pad_len = len(text), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	ciphertext = [0] * (n + pad_len)
	if hint is not None:
		hm, hiv, hct = hint
		assert isinstance(hm, bytes) and isinstance(hiv, bytes) and isinstance(hct, bytes)
		assert len(hm) == pad_len and len(hct) == pad_len and len(hiv) == pad_len
		for i in range(pad_len):
			ciphertext[n - pad_len + i] = hm[i] ^ hiv[i] ^ text[n - pad_len + i]
			ciphertext[n + i] = hct[i]
	q, qi = [(ciphertext[:], n // pad_len - 1 - int(hint is not None), pad_len - 1)], 0
	res = []
	while qi < len(q):
		(ciphertext, i, j), qi = q[qi], qi + 1
		print(f"[INFO] <forge_CBC_ciphertext_with_padding_oracle> Forging block {i} at index {j} on {ciphertext}")
		for k in range(j + 1, pad_len):
			ciphertext[pad_len * i + k] ^= pad_len - j ^ pad_len - j - 1
		candidate = []
		for x in range(2**8):
			ciphertext[pad_len * i + j] = x
			resp = padding_oracle(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : pad_len * (i + 2)]))
			assert isinstance(resp, bool)
			if not resp:
				continue
			if j == pad_len - 1:
				ciphertext[pad_len * i + j - 1] = ciphertext[pad_len * i + j - 1] + 1 & 2**8 - 1
				resp = padding_oracle(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : pad_len * (i + 2)]))
				assert isinstance(resp, bool)
				if not resp:
					continue
			candidate.append(x)
			if not faulty:
				break
		if not faulty and len(candidate) == 0:
			print(f"[ERROR] <forge_CBC_ciphertext_with_padding_oracle> Failed to forge block {i}, sub index {j}, index {pad_len * i + j}")
			assert False
		for x in candidate:
			next_ciphertext = ciphertext[: pad_len * i + j] + [x] + ciphertext[pad_len * i + j + 1 :]
			if j > 0:
				q.append((next_ciphertext[:], i, j - 1))
			else:
				for k in range(pad_len):
					next_ciphertext[pad_len * i + k] ^= text[pad_len * i + k] ^ pad_len
				if i == 0:
					res.append(next_ciphertext[:])
				else:
					q.append((next_ciphertext[:], i - 1, pad_len - 1))
	res = [(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : ])) for ciphertext in res]
	return res[0] if not faulty else res

# Hint is a tuple of (message, iv, ciphertext) which are bytes of length 16
# padding_oracle_request(iv, ciphertext) checks whether the text is padded, whose result can be read from padding_oracle_read()
# if faulty, padding_oracle returns True on some instances where it should return False
# Returns a tuple of iv and ciphertext if not faulty, otherwise all possible such tuples
def forge_CBC_ciphertext_with_batched_padding_oracle(text : bytes, padding_oracle_request, padding_oracle_read, hint = None, faulty = False):
	n, pad_len = len(text), 16
	assert pad_len > 0 and n % pad_len == 0 and n > 0
	ciphertext = [0] * (n + pad_len)
	if hint is not None:
		hm, hiv, hct = hint
		assert isinstance(hm, bytes) and isinstance(hiv, bytes) and isinstance(hct, bytes)
		assert len(hm) == pad_len and len(hct) == pad_len and len(hiv) == pad_len
		for i in range(pad_len):
			ciphertext[n - pad_len + i] = hm[i] ^ hiv[i] ^ text[n - pad_len + i]
			ciphertext[n + i] = hct[i]
	q, qi = [(ciphertext[:], n // pad_len - 1 - int(hint is not None), pad_len - 1)], 0
	res = []
	while qi < len(q):
		(ciphertext, i, j), qi = q[qi], qi + 1
		print(f"[INFO] <forge_CBC_ciphertext_with_batched_padding_oracle> Forging block {i} at index {j} on {ciphertext}")
		for k in range(j + 1, pad_len):
			ciphertext[pad_len * i + k] ^= pad_len - j ^ pad_len - j - 1
		query = []
		for x in range(2**8):
			ciphertext[pad_len * i + j] = x
			padding_oracle_request(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : pad_len * (i + 2)]))
			query.append(x)
			if j == pad_len - 1:
				ciphertext[pad_len * i + j - 1] = ciphertext[pad_len * i + j - 1] + 1 & 2**8 - 1
				padding_oracle_request(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : pad_len * (i + 2)]))
				query.append(x)
		candidate = []
		ok = [True] * 2**8
		for x in query:
			resp = padding_oracle_read()
			assert isinstance(resp, bool)
			if not resp:
				ok[x] = False
		candidate = [x for x in range(2**8) if ok[x]]
		if not faulty and len(candidate) != 1:
			print(f"[ERROR] <forge_CBC_ciphertext_with_batched_padding_oracle> Failed to forge block {i}, sub index {j}, index {pad_len * i + j}")
			assert False
		for x in candidate:
			next_ciphertext = ciphertext[: pad_len * i + j] + [x] + ciphertext[pad_len * i + j + 1 :]
			if j > 0:
				q.append((next_ciphertext[:], i, j - 1))
			else:
				for k in range(pad_len):
					next_ciphertext[pad_len * i + k] ^= text[pad_len * i + k] ^ pad_len
				if i == 0:
					res.append(next_ciphertext[:])
				else:
					q.append((next_ciphertext[:], i - 1, pad_len - 1))
	res = [(bytes(ciphertext[ : pad_len]), bytes(ciphertext[pad_len : ])) for ciphertext in res]
	return res[0] if not faulty else res

if __name__ == "__main__":
	from Crypto.Cipher import AES
	from Crypto.Util.Padding import pad, unpad
	key = pad(b"testiv_zz", 16)
	challenge_text = pad(b"Test_text_123234234!!{testing_zzzzzzzzz}_1232342245234234243", 16)
	hm = pad(b"hint_message", 16)
	hiv = pad(b"hint_iv", 16)
	hct = AES.new(key, AES.MODE_CBC, hiv).encrypt(hm)

	def padding_oracle(iv : bytes, ciphertext : bytes):
		cipher = AES.new(key, AES.MODE_CBC, iv)
		try:
			unpad(cipher.decrypt(ciphertext), 16)
			return True
		except Exception as e:
			return False

	iv, ciphertext = forge_CBC_ciphertext_with_padding_oracle(challenge_text, padding_oracle)
	assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(challenge_text)
	iv, ciphertext = forge_CBC_ciphertext_with_padding_oracle(challenge_text, padding_oracle, (hm, hiv, hct))
	assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(challenge_text)

	ri = 0
	res = []

	def padding_oracle_request(iv : bytes, ciphertext : bytes):
		cipher = AES.new(key, AES.MODE_CBC, iv)
		try:
			unpad(cipher.decrypt(ciphertext), 16)
			res.append(True)
		except Exception as e:
			res.append(False)

	def padding_oracle_read():
		global ri, res
		assert ri < len(res)
		ri += 1
		return res[ri - 1]

	iv, ciphertext = forge_CBC_ciphertext_with_batched_padding_oracle(challenge_text, padding_oracle_request, padding_oracle_read)
	assert ri == len(res)
	assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(challenge_text)
	iv, ciphertext = forge_CBC_ciphertext_with_batched_padding_oracle(challenge_text, padding_oracle_request, padding_oracle_read, (hm, hiv, hct))
	assert ri == len(res)
	assert ciphertext == AES.new(key, AES.MODE_CBC, iv).encrypt(challenge_text)

"""
Tested on
- PatriotCTF2024/crypto/Protected Console
"""