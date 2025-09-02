# filename: solve.py
import sys
from Crypto.Util.number import inverse
from Crypto.Cipher import AES

# --- PART 1: RSA Private Key Reconstruction (Verified Correct) ---
p = 8864232758513159703894059401865610546024920396843264690204008679925886187595802637186841391387878400972316394349580079216245335878969631424028047238814217
q = 8864232758513159703894059401865610546024920396843264690204008679925886187595802637186841391387878400972316394349580079216245335878969631424028047238815239
n_hex = "6FE4DBA45F9D40226FEF01F4FA4039EEA9A9001266C4730F14DF7FAAC4A086046A9246425DD0B0328CF51540D2CFBC31E0B73FDEA75EE49E178CC4A555D83B9E99C28980FF420B7FF9B8A02E7F26B38EB3DD40E519D4CEA7804D6B9172198778D3FC8DA2D2D225FD3ED7AAFB2F5262B70F3C313E2DF7944CA678D10E5659C43F"
e_hex = "010001"
n = int(n_hex, 16)
e = int(e_hex, 16)
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# --- PART 2: Decrypt and VERIFY Session Key (Verified Correct) ---
try:
	with open('enc.bin', 'rb') as f:
		encrypted_data = f.read()
except FileNotFoundError:
	sys.exit("[FATAL] 'enc.bin' not found. Please run 'gpg --dearmor < enc.asc > enc.bin' first.")

packet1_body = encrypted_data[2:142]
mpi_bytes = packet1_body[10:]
mpi_bit_length = int.from_bytes(mpi_bytes[:2], 'big')
mpi_byte_length = (mpi_bit_length + 7) // 8
encrypted_session_key_int = int.from_bytes(mpi_bytes[2 : 2 + mpi_byte_length], 'big')

key_len_bytes = (n.bit_length() + 7) // 8
decrypted_padded_m_int = pow(encrypted_session_key_int, d, n)
decrypted_padded_m_bytes = decrypted_padded_m_int.to_bytes(key_len_bytes, 'big')

if decrypted_padded_m_bytes[0:2] != b'\x00\x02':
	sys.exit("[FATAL] RSA decryption failed or PKCS#1 v1.5 padding is incorrect.")
separator_idx = decrypted_padded_m_bytes.find(b'\x00', 2)
session_key_material = decrypted_padded_m_bytes[separator_idx + 1:]
sym_algo_id = session_key_material[0]
session_key = session_key_material[1:33]
checksum_from_packet = int.from_bytes(session_key_material[33:35], 'big')
calculated_checksum = sum(session_key) & 0xFFFF

if calculated_checksum != checksum_from_packet:
	sys.exit("[FATAL] Session key checksum MISMATCH!")
print("--- Session key checksum PASSED. The key is correct. ---")

# --- PART 3: Correct OpenPGP CFB Decryption with Correct Segment Size ---
seipd_packet = encrypted_data[142:]
seipd_body = seipd_packet[2:]
version_byte = seipd_body[0]
if version_byte != 1:
	sys.exit(f"[FATAL] Expected SEIPD version 1, but found {version_byte}")
ciphertext = seipd_body[1:]

block_size = AES.block_size
iv_zeros = b'\x00' * block_size

# CRITICAL FIX: Explicitly set segment_size to 128 bits for full-block feedback.
cipher_cfb = AES.new(session_key, AES.MODE_CFB, iv=iv_zeros, segment_size=128)
decrypted_data_with_mdc = cipher_cfb.decrypt(ciphertext)

# Perform the prefix integrity check on the decrypted data
prefix_plaintext = decrypted_data_with_mdc[:block_size + 2]
if prefix_plaintext[-2:] != prefix_plaintext[-4:-2]:
	sys.exit("[FATAL] Prefix integrity check failed.")
print("--- Prefix integrity check PASSED. Decrypting... ---")

# --- PART 4: MDC Removal and Final Output ---
plaintext = decrypted_data_with_mdc[:-22]

print("\n--- DECRYPTED MESSAGE ---")
try:
	# The actual message data starts after the random prefix.
	message_data = plaintext[block_size + 2:]
	print(message_data.decode('utf-8'))
except UnicodeDecodeError:
	print(message_data)
print("-------------------------")