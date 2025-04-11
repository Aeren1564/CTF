from CTF_Library import *

data = open('bin/libhash.so', 'rb').read()
a1_xor_box = data[0x3060:0x3160]
state_replace = data[0x3160:0x3260]
indexshiftbox = data[0x3260:0x3360][:240]
kshiftbox = data[0x3360:0x3460][:128]

def check(s):
	for x in s:
		print(f"{x:0{8}b}")
	print()
#check(a1_xor_box)
#check(state_replace)
#check(indexshiftbox)
#check(kshiftbox)

word = []
with open("word.txt") as file:
	word = list(s for s in file.read().split("\n") if len(s) == 2)
print(f"{len(word) = }")

def _hash_compute(bandit_salt, input_data):
	"""
	Compute a hash from the input data.

	Args:
		bandit_salt: the
		input_data: A bytes-like object representing the input data

	Returns:
		A list of 2 integers (the computed hash)
	"""
	# Allocate memory for block_data (16 bytes)
	block_data = bytearray(16)

	# Copy values from a1 to ptr
	ptr = bandit_salt

	# Process data in chunks of 16 bytes
	i = 0
	while i <= len(input_data):
		for j in range(16):
			if j + i >= len(input_data):
				block_data[j] = len(input_data) - i
			else:
				block_data[j] = input_data[i + j]

		ptr = inner(ptr, block_data, bandit_salt)
		i += 16

	return ptr


def inner(ptr, block_data, bandit_salt):
	"""
	Manipulate bytes in a1 based on a2 and a3.

	Args:
		ptr: the
		block_data: A bytearray of 16 bytes
		bandit_salt: A list of 2 integers (QWORDs)

	Returns:
		Nothing (modifies a1 in-place)
	"""
	# Convert a1 to a bytearray for byte-level operations
	ptr_modifiable = bytearray(ptr)

	state = bytearray(24)

	for i in range(15):  # 0 to 14
		for j in range(16):  # 0 to 15
			index = j | (16 * i)
			shift = indexshiftbox[index] >> 4
			mask = indexshiftbox[index] & 0xF

			ptr_modifiable[j] ^= a1_xor_box[bandit_salt[shift] ^ block_data[j] ^ bandit_salt[mask]]
			state[j] = state_replace[ptr_modifiable[j]]
			ptr_modifiable[j] = 0

		for k in range(128):  # 0 to 127
			byte_index = k >> 3
			bit_index = k & 7

			shift1 = kshiftbox[k] >> 3
			shift2 = kshiftbox[k] & 7

			ptr_modifiable[byte_index] ^= (((state[shift1] >> shift2) & 1) << bit_index)

	return bytes(ptr_modifiable)

bandit_salt = bytes.fromhex('588fe10356c0412c74a5db5f8f1f1930')
def hash_compute(x):
	return _hash_compute(bandit_salt, x)

a = b"a\x00" + os.urandom(14)
b = b"b\x00" + os.urandom(14)

print(hash_compute(a + b"\x01" + b))
print(hash_compute(b + b"\x01" + a))

"""
Ax+a
Bx+b

ABx+Ab+a
BAx+Ba+b
"""