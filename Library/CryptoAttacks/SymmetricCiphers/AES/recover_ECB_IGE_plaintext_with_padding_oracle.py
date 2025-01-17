# padding_oracle(m0, c0, ciphertext) checks whether the text is padded
def recover_ECB_IGE_plaintext_with_padding_oracle(m0 : bytes, c0 : bytes, ciphertext : bytes, padding_oracle, execution_type : str = "naive"):
	assert execution_type in ["naive", "thread"]
	if execution_type == "thread":
		from concurrent.futures import ThreadPoolExecutor
		import os
	n, pad_len = len(ciphertext), 16
	assert pad_len > 0 and n % pad_len == 0 and len(m0) == len(c0) == pad_len
	plaintext = list(m0) + [0] * n
	ciphertext = list(c0 + ciphertext)
	for i in range(n // pad_len):
		temp = ciphertext[pad_len * i : pad_len * (i + 2)]
		for j in reversed(range(pad_len)):
			if execution_type == "naive":
				cur = temp[:]
				for x in range(256):
					cur[j] = x
					if padding_oracle(bytes(plaintext[pad_len * i : pad_len * (i + 1)]), bytes(cur[: pad_len]), bytes(cur[pad_len :])):
						if j == 0:
							temp[j] = x
							print(f"[INFO] <recover_ECB_IGE_plaintext_with_padding_oracle>J Index {pad_len * i + j} matched with {x}")
							break
						cur[j - 1] = (cur[j - 1] + 1) % 256
						if padding_oracle(bytes(plaintext[pad_len * i : pad_len * (i + 1)]), bytes(cur[: pad_len]), bytes(cur[pad_len :])):
							temp[j] = x
							print(f"[INFO] <recover_ECB_IGE_plaintext_with_padding_oracle>J Index {pad_len * i + j} matched with {x}")
							break
				else:
					print(f"[ERROR] <recover_ECB_IGE_plaintext_with_padding_oracle> Failed to recover byte at index {pad_len * i + j}")
					assert False
			elif execution_type == "thread":
				def solve_for_remainder(rem):
					cur = temp[:]
					for x in range(rem, 256, os.cpu_count()):
						cur[j] = x
						if padding_oracle(bytes(plaintext[pad_len * i : pad_len * (i + 1)]), bytes(cur[: pad_len]), bytes(cur[pad_len :])):
							if j == 0:
								return x
							cur[j - 1] = (cur[j - 1] + 1) % 256
							if padding_oracle(bytes(plaintext[pad_len * i : pad_len * (i + 1)]), bytes(cur[: pad_len]), bytes(cur[pad_len :])):
								return x
				with ThreadPoolExecutor(max_workers = os.cpu_count()) as executor:
					for x in executor.map(solve_for_remainder, range(os.cpu_count())):
						if x != None:
							temp[j] = x
							print(f"[INFO] <recover_ECB_IGE_plaintext_with_padding_oracle>J Index {pad_len * i + j} matched with {x}")
							break
					else:
						print(f"[ERROR] <recover_ECB_IGE_plaintext_with_padding_oracle> Failed to recover byte at index {pad_len * i + j}")
						assert False
			else:
				print(f"[ERROR] <recover_ECB_IGE_plaintext_with_padding_oracle> Invalid execution type")
				assert False
			for k in range(j, pad_len):
				temp[k] ^= pad_len - j ^ pad_len - j + 1
		for j in range(pad_len):
			plaintext[pad_len * (i + 1) + j] = ciphertext[pad_len * i + j] ^ temp[j] ^ pad_len + 1
	return bytes(plaintext[pad_len : ])
