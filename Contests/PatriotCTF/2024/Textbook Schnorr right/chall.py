from sage.all import *
import secrets
import hashlib
import os

def FLAG():
    with open('flag.txt') as f:
        flag = f.read()
        print(f"Congrats your flag is: {flag}")	

# secp256k1 curve parameters
p = [<REDACTED>]
q = [<REDACTED>]
K = GF(p)
a = K([<REDACTED>])
b = K([<REDACTED>])
E = EllipticCurve(K, (a, b))
G = E([<REDACTED>], [<REDACTED>])

x = secrets.randbelow(q)
P = x * G
print(f"Public Key: {P}")

def btoi(b):
    return int.from_bytes(b, 'big')
    
def itob(i):
    return i.to_bytes((int(i).bit_length()+7)//8, 'big')

def compute_hash(target):
    return int(hashlib.sha256(str(target).encode()).hexdigest(), 16) % q

def schnorr_sign(message):
    r = secrets.randbelow(q)
    R = r * G
    Ri = int(R.xy()[0] + R.xy()[1])
    print(Ri, Ri.bit_length())
    h = compute_hash(Ri | message)
    s = r + x*h
    return (s, R)

def schnorr_verify(message, s, R):
    Ri = int(R.xy()[0] + R.xy()[1])
    print(Ri, Ri.bit_length())
    h = compute_hash(Ri | message)
    return s*G == R + h*P 

assert(schnorr_verify(btoi("test".encode()), *schnorr_sign(btoi("test".encode()))))

def verify_message(separator, words, signature):

    message = separator.join([w.encode() for w in words]) + separator
    message_binary = int.from_bytes(message, byteorder='big')
   
    s_test, R_test  = signature
    if schnorr_verify(message_binary, s_test, R_test):
        FLAG()
        exit()
    else:
        exit()

separator_hex = input("Enter separator as a hex value (2 digits): ")
separator = bytes.fromhex(separator_hex)

try: 
    words_hex = [input(f"Enter 3-letter word {i+1} as a hex value (6 digits): ") for i in range(8)]
    words = [bytes.fromhex(word_hex).decode('ascii', errors='strict') for word_hex in words_hex]
except:
    print("Words are not valid ascii!")
    exit()
    
if len(words) != 8 or any([len(w) != 3 for w in words]):
    print("Words must be 3-letter ASCII words.")
    exit()

x_R = int(input("Enter the x-coordinate of signature R: "), 16)
y_R = int(input("Enter the y-coordinate of signature R: "), 16)

signature_s = int(input("Enter signature s: "), 16)

if signature_s >= q or signature_s <= 0
    print("illegal value of s")
    exit()

try:
    R = E(x_R, y_R)
except:
    print("Point does not lie on the curve")
    exit()

verify_message(separator, words, (signature_s, R))