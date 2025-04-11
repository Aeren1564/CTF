from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os
import base64
import random

#FLAG regex is TFCCTF{[bdefgmnprsu012345_]+}

FLAG = b'TFCCTF{bdefgmnprsu012345_bdefgm}' 

def custom_unpad(ct):
    ct = base64.b64decode(ct)
    iv, ct = ct[:16], ct[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = cipher.decrypt(ct)
    padding = True
    try:
        unpad(pt, 16)
    except:
        padding = False
    padding = (padding | (random.randint(1,10) > 7) ) & (random.randint(1,10) <= 7)
    # return false with prob 3/10
    # return padding with prob 7/10
    return padding

current = 0
limit = 10000
key = os.urandom(16)
iv = os.urandom(16)
cipher = AES.new(key, AES.MODE_CBC, iv)
ct = cipher.encrypt(FLAG)

give = base64.b64encode(iv + ct)
print(f"Lets see you decode this: {give.decode()}")
print("I made my unpad truly random, there is nothing you can do, just give up already")

while True:
    if current > limit:
        exit()
    to_unpad = input()
    out = custom_unpad(to_unpad)
    print(out)
    current+=1

# e8VNtkG5vUUsjdX4vjKJDW4doxhKU/VRe4qCovJnHl0/SLXPRBjehKMLBo6pj/uO/4gReQIod1i/3dXT8od2DQ== 
