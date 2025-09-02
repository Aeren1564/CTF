from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from functools import reduce
from secret import flag
from struct import pack
import os

BLOCK_SIZE = 16
key_ctr = os.urandom(BLOCK_SIZE)
iv = os.urandom(BLOCK_SIZE)
init_tag = os.urandom(16)


def AES_ECB_enc(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.encrypt(message)


def AES_ECB_dec(key, message):
    enc = AES.new(key, AES.MODE_ECB)
    return enc.decrypt(message)


# Takes any number of arguements, and return the xor result.
# Similar to pwntools' xor, but trucated to minimum length
def xor(*args):
    def _xor(x1, x2): return x1 ^ x2
    return bytes(map(lambda x: reduce(_xor, x, 0), zip(*args)))


def batched(items, blocksize):
    idx = 0
    while idx + blocksize < len(items):
        yield items[idx:idx+blocksize]
        idx += blocksize
    yield items[idx:]
    return


def counter(nonce):
    count = 0
    while count < 2**(16 - len(nonce)):
        yield nonce + str(count).encode().rjust(16-len(nonce), b"\x00")
        count += 1
    return

# irreducible, primitive poly x^8 + x^4 + x^3 + x^2 + 1


def granular_mult(a: int, b: int) -> int:
    c = 0
    for i in range(8, -1, -1):
        if (a >> i) & 1:
            c ^= b

        if b & 1:
            b = (b >> 1) ^ 0b10111000
        else:
            b >>= 1

    return c


def update_tag(granular_key, current_tag, block):
    new_tag = [0 for i in range(16)]
    for i in range(16):
        new_tag[i] = granular_mult(current_tag[i], granular_key[i]) ^ block[i]
    return bytes(new_tag)


def encrypt(message):
    cipher = b""
    nonce = os.urandom(8)
    enc_counter = counter(nonce)
    granular_key = AES_ECB_enc(key_ctr, b"\x00"*16)
    tag_mask = AES_ECB_enc(key_ctr, next(enc_counter))
    tag = init_tag
    for block in batched(message, 16):
        ctr_block = AES_ECB_enc(key_ctr, next(enc_counter))
        cur_block_ct = xor(block, ctr_block)
        cipher += cur_block_ct
        tag = update_tag(granular_key, tag, cur_block_ct.ljust(16, b"\x00"))
    tag = update_tag(granular_key, tag, pack("<QQ", 0, len(message)))
    final_tag = xor(tag, tag_mask)

    return nonce + final_tag + cipher


def decrypt(cipher):
    message = b""
    nonce = cipher[:8]
    cipher_tag = cipher[8:24]
    cipher_text = cipher[24:]

    # authenticate the cipher
    enc_counter = counter(nonce)
    granular_key = AES_ECB_enc(key_ctr, b"\x00"*16)
    tag_mask = AES_ECB_enc(key_ctr, next(enc_counter))
    tag = init_tag
    for block in batched(cipher_text, 16):
        tag = update_tag(granular_key, tag, block.ljust(16, b"\x00"))
    tag = update_tag(granular_key, tag, pack("<QQ", 0, len(cipher_text)))
    tag = xor(tag, tag_mask)

    if tag != cipher_tag:
        raise ValueError("Unauthenticated Message")

    for block in batched(cipher_text, 16):
        ctr_block = AES_ECB_enc(key_ctr, next(enc_counter))
        message += xor(block, ctr_block)

    return message


def main():
    print(f"""
*********************************************************

Certificate as a Service

************************* Menu **************************

1. Generate random certificate
2. Verify certificate

*********************************************************
""")
    for queries in range(0x137):
        option = input("> ")
        if option == "1":
            cert_length = int(
                input("Give me the length of the desire certificate: "))
            cert = os.urandom(cert_length)
            print(f"Here is your certificate for {cert.hex()}:")
            print(f"{encrypt(cert).hex()}")
        elif option == "2":
            try:
                cert = bytes.fromhex(input("Give me a certificate >> "))
                if len(cert) < 32:
                    print("Your certificate is not long enough!")
                    continue

                if len(cert) > 32*32:
                    print("Your certificate is too long!")
                    continue

                message = decrypt(cert)
                if b"give me the flag!!!" in message:
                    print("This certificate grants you the flag!")
                    print(flag)
                    print(f"You used {queries} queries")
                    break
                else:
                    print("This certificate seems to give you nothing...")
            except Exception:
                print("Something went wrong")
        else:
            print("Invalid Option")


if __name__ == "__main__":
    main()
