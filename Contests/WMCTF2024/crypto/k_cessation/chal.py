from typing import List,Union,Literal
from Crypto.Util.number import long_to_bytes
import secrets
import random,string,re

class K_Cessation:
    '''
    ## Background:
    K-Cessation cipher is a cipher that uses a K bit wheel to pick the next cipher bit from plaintext bit.
    When encryption starts, the wheel starts at the last bit of the wheel.
    The wheel loops around when it reaches the end.
    For every plaintext bit, the wheel is rotated to the next bit in the wheel that matches the plaintext bit, and the distance rotated is appended to the ciphertext.

    Therefore, if the wheel is not known, it is not possible to decrypt the ciphertext. 
    Or is it?

    
    ## Example:
    To encode "youtu.be/dQw4w9WgXcQ" in 64-Cessation with the wheel 1100011011100011100110100011110110010110010100001011111011111010:
    1. convert the plaintext to bits: 01111001 01101111 01110101 01110100 01110101 00101110 01100010 01100101 00101111 01100100 01010001 01110111 00110100 01110111 00111001 01010111 01100111 01011000 01100011 01010001
    2. from wheel[-1] to the next "0" bit in the wheel, distance is 3, the current wheel position is wheel[2]
    3. from wheel[2] to the next "1" bit in the wheel, distance is 3, the current wheel position is wheel[5]
    4. repeat the steps until all bits is encoded
    5. the result is 3312121232111411211311221152515233123332223411313221112161142123243321244111111311111112111131113211132412111212112112321122115251142114213312132313311222111112


    ## Challenge:
    A flag is encoded with 64-Cessation cipher. 
    The wheel is not known. 
    The ciphertext is given in ciphertext.txt.
    The flag is only known to be an ascii string that is longer than 64 characters. 
    No part of the flag is known, which means the flag is NOT in WMCTF{} or FLAG{} format.
    When submitting, please make the flag in WMCTF{} format.
    The most significant bit of each byte is flipped with a random bit.
    You need to extract the flag from the ciphertext and submit it.
    For your convenience, a salted sha256 hash of the flag is given in flag_hash.txt.

    '''

    def __is_valid_wheel(self):
        hasZero = False
        hasOne = False
        for i in self.wheel:
            if not isinstance(i,int):
                raise ValueError("Wheel must be a list of int")
            if i == 0:
                hasZero = True
            elif i == 1:
                hasOne = True
            if i > 1 or i < 0:
                raise ValueError("Wheel must be a list of 0s and 1s")
        if not hasZero or not hasOne:
            raise ValueError("Wheel must contain at least one 0 and one 1")

    def __init__(self,wheel:List[int]):
        self.wheel = wheel
        self.__is_valid_wheel()
        self.state = -1
        self.finalized = False
    def __find_next_in_wheel(self,target:Literal[1,0]) -> List[int]:
        result = 1
        while True:
            ptr = self.state + result
            ptr = ptr % len(self.wheel)
            v = self.wheel[ptr]
            if v == target:
                self.state = ptr
                return [result]
            result+=1
    def __iter_bits(self,data:bytes):
        for b in data:
            for i in range(7,-1,-1):
                yield (b >> i) & 1
    def __check_finalized(self):
        if self.finalized:
            raise ValueError("This instance has already been finalized")
        self.finalized = True
    def encrypt(self,data:Union[str,bytes]) -> List[int]:
        self.__check_finalized()
        if isinstance(data,str):
            data = data.encode()
        out = []
        for bit in self.__iter_bits(data):
            rs = self.__find_next_in_wheel(bit)
            # print(f"bit={bit},rs={rs},state={self.state}")
            out.extend(rs)
        return out
    
    def decrypt(self,data:List[int]) -> bytes:
        self.__check_finalized()
        out = []
        for i in data:
            assert type(i) == int
            self.state = self.state + i
            self.state %= len(self.wheel)
            out.append(self.wheel[self.state])
        long = "".join(map(str,out))
        return long_to_bytes(int(long,2))

# generate a random wheel with k bits.
def random_wheel(k=64) -> List[int]:
    return [secrets.randbelow(2) for _ in range(k)]

# the most significant bit of each byte is flipped with a random bit.
def encode_ascii_with_random_msb(data:bytes) -> bytes:
    out = bytearray()
    for b in data:
        assert b < 128, "not ascii"
        b = b ^ (0b10000000 * secrets.randbelow(2))
        out.append(b)
    return bytes(out)

# for your convenience, here is the decoding function.
def decode_ascii_with_random_msb(data:bytes) -> bytes:
    out = bytearray()
    for b in data:
        b = b & 0b01111111
        out.append(b)
    return bytes(out)


if __name__ == "__main__":
    try:
        from flag import flag
        from flag import wheel
    except ImportError:
        print("flag.py not found, using test flag")
        flag = "THIS_IS_TEST_FLAG_WHEN_YOU_HEAR_THE_BUZZER_LOOK_AT_THE_FLAG_BEEEP"
        wheel = random_wheel(64)

    # wheel is wheel and 64 bits
    assert type(wheel) == list and len(wheel) == 64 and all((i in [0,1] for i in wheel))
    # flag is flag and string
    assert type(flag) == str
    # flag is ascii
    assert all((ord(c) < 128 for c in flag))
    # flag is long
    assert len(flag) > 64
    # flag does not start with wmctf{ nor does it end with }
    assert not flag.lower().startswith("wmctf{") and not flag.endswith("}")
    # flag also does not start with flag{
    assert not flag.lower().startswith("flag{")

    # the most significant bit of each byte is flipped with a random bit.
    plaintext = encode_ascii_with_random_msb(flag.encode())

    c = K_Cessation(wheel)
    ct = c.encrypt(plaintext)
    with open("ciphertext.txt","w") as f:
        f.write(str(ct))

    import hashlib
    # for you can verify the correctness of your decryption.
    # or you can brute force the flag hash, it is just a >64 length string :)
    with open("flag_hash.txt","w") as f:
        salt = secrets.token_bytes(16).hex()
        h = hashlib.sha256((salt + flag).encode()).hexdigest()
        f.write(h + ":" + salt)

    # demostration that decryption works
    c = K_Cessation(wheel)
    pt = c.decrypt(ct)
    pt = decode_ascii_with_random_msb(pt)
    print(pt)
    assert flag.encode() in pt