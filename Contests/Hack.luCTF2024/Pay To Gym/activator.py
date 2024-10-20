import random
import sympy
from Crypto.Util.number import inverse
from Crypto.Hash import SHA1
from Crypto.Cipher import AES

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def generate_prime():
    while True:
        p = random.getrandbits(256)
        if sympy.isprime(p):
            return p

def generate_keys():
    while True:
        p = generate_prime()
        q = generate_prime()

        if p == q:
            continue

        n = p * q
        phi = (p - 1) * (q - 1)
        e = 65537

        if gcd(e, phi) == 1:
            break

    d = inverse(e, phi)
    return ((e, n), (d, n))

def verify(s, pubk):
    e, n = pubk
    return pow(s, e, n)

def sign(m, pk):
    d, n = pk
    return pow(m, d, n)

def encrypt(pk, otp, sqn):
    if sqn.bit_length() > 16 or otp.bit_length() > 256:
        return 0
    
    sqn_bin = f"{sqn:016b}"
    otp_bin = f"{otp:0256b}"   
    m = sqn_bin + otp_bin

    h = SHA1.new()
    h.update(m.encode())

    m = int(m, 2)
    s = sign(m, pk)
    return (s, h.hexdigest())

def activator(enc):
    pubk, pk = generate_keys()
    pubk_pin = (65537, 10418337868798443858901820790977066288221460515275090946243785628154408062569898328025289026686304809160241911029126122415897106930156444377187260816798137)
    s, h = enc

    if (int(s) == 0):
        return 0

    m = verify(s, pubk_pin)
    m_bin = f"{m:0272b}"

    h_ = SHA1.new()
    h_.update(m_bin.encode())

    if h != h_.hexdigest():
        return 0

    otp_a = random.getrandbits(256)
    otp_a_bin = f"{otp_a:0256b}"

    otp_c = m_bin[16:272]
    sqn = m_bin[:16]
    sqn = f"{int(sqn, 2) + 1:016b}"

    if len(otp_c) != len(otp_a_bin):
        return 0

    sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c, otp_a_bin))

    if len(sess_k) < 256:
        raise "C"

    sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')
    iv = random.getrandbits(128).to_bytes(16, byteorder='big')
    
    aes = AES.new(sess_k, AES.MODE_CBC, iv)

    p = "authenticated. flag{not_a_real_flag}".encode()
    pad_len = 16 - (len(p) % 16)
    pad = bytes([pad_len] * pad_len)
    c = aes.encrypt(p + pad)

    return (encrypt(pk, otp_a, int(sqn, 2)), pubk, c, iv)

def card_terminal():
    pubk, pk =  bro,ken
    
    sqn = random.getrandbits(16)
    
    otp_c = random.getrandbits(256)
    otp_c_bin = f"{otp_c:0256b}"
    
    (s, h), pubk_pin, c, iv = activator(encrypt(pk, otp_c, sqn))
    if s == 0:
        return 0
    
    m = verify(s, pubk_pin)
    m_bin = f"{m:0272b}"
    otp_a_bin = m_bin[16:272]
    
    sess_k = ''.join(str(int(a) ^ int(b)) for a, b in zip(otp_c_bin, otp_a_bin))
    sess_k = int(sess_k, 2).to_bytes(32, byteorder='big')

    aes = AES.new(sess_k, AES.MODE_CBC, iv)
    p = aes.decrypt(c)

    pad_len = p[-1]

    if p[-pad_len:] != bytes([pad_len] * pad_len):
        return 0

    p = p[:-pad_len]

    print(p.decode('utf-8'))

if __name__ == "__main__":
    try:
        card_terminal()
    except Exception as e:
        # Allow for external card terminals
        try:
            (s, h), pubk_pin, c, iv = activator((int(input("s: ")), input("h: ")))
            print(s)
            print(pubk_pin)
            print(c.hex())
            print(iv.hex())
        except Exception:
            print("Invalid Input")
