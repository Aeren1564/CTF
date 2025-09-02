from Crypto.Cipher import AES
import hashlib
import x25519
import os

flag = "acsc{######## REDACTED ########}"
assert len(flag) == 32

def validate_pubkey(pubkey):
    if len(pubkey) != 32:
        print("Invalid length!")
        exit(0)
    if not (1 < x25519.djbec.decodeint(pubkey) < 2**255 - 20):
        print("Invalid public key!")
        exit(0)

def pad(m):
    padlen = 16 - len(m) % 16
    return m + bytes([padlen] * padlen)

def mitm(pubkey):
    while (yn := input("MITM? [y/n] >>> ").lower()) not in ["y", "n"]:
        pass
    if yn == "y":
        return bytes.fromhex(input("MITM'd Public Key >>> "))
    else:
        return pubkey

a_privkey = os.urandom(32)
a_pubkey = x25519.scalar_base_mult(a_privkey)

print("Public Key of A:", a_pubkey.hex())
a_mitm_pubkey = mitm(a_pubkey)
validate_pubkey(a_mitm_pubkey)

b_privkey = os.urandom(32)
b_pubkey = x25519.scalar_base_mult(b_privkey)

print("Public Key of B:", b_pubkey.hex())
b_mitm_pubkey = mitm(b_pubkey)
validate_pubkey(b_mitm_pubkey)

a_secret = x25519.scalar_mult(a_privkey, b_mitm_pubkey)
b_secret = x25519.scalar_mult(b_privkey, a_mitm_pubkey)

a_safety_number = int("0x" + hashlib.sha256(a_secret).hexdigest(), 16) % (10 ** 32)
b_safety_number = int("0x" + hashlib.sha256(b_secret).hexdigest(), 16) % (10 ** 32)

print("Safety Number of A:", a_safety_number)
print("Safety Number of B:", b_safety_number)

if a_safety_number != b_safety_number:
    print("Safety check failed. Probably MITM...")
    exit(0)

print("Safety check succeeded. Let's start chatting!")

a_cipher = AES.new(a_secret, AES.MODE_CBC)
print("A:", (a_cipher.iv + a_cipher.encrypt(pad(f"Half of the flag was `{flag[:16]}`. What was the other?".encode()))).hex())

b_cipher = AES.new(b_secret, AES.MODE_CBC)
print("B:", (b_cipher.iv + b_cipher.encrypt(pad(f"Uhhh wait a sec... not sure but probably `{flag[16:]}`?".encode()))).hex())
