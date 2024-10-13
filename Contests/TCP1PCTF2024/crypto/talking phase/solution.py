from CTF_Library import *
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

with remote("ctf.tcp1p.team", 1965) as io:
	fake_priv_A = rsa.generate_private_key(public_exponent=65537,key_size=2048,)
	fake_pub_A = fake_priv_A.public_key()

	def encode_pubkey(pubkey):
		return base64.b64encode(pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

	def encrypt_message(pubkey, plaintext: bytes):
		return base64.b64encode(pubkey.encrypt(plaintext, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)))

	def decrypt_message(privkey, ciphertext: bytes):
		return privkey.decrypt(base64.b64decode(ciphertext), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))

	enc_fake_pubkey_A = encode_pubkey(fake_pub_A)
	io.sendlineafter(b"(tamper): ", enc_fake_pubkey_A).decode()
	io.readuntilS(b"Entity B: ")
	real_pub_B = serialization.load_pem_public_key(base64.b64decode(io.readline().strip()))
	io.sendlineafter(b"(tamper): ", b"fwd").decode()
	enc_message = encrypt_message(real_pub_B, b"giv me the flag you damn donut")
	io.sendlineafter(b"(tamper): ", enc_message).decode()
	io.readuntilS(b": ")
	print(decrypt_message(fake_priv_A, io.readline().strip()))
