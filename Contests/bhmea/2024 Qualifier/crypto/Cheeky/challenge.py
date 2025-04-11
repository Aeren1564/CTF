#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Medium] Crypto - Cheeky
#

# Native imports
import os, time, json
from hashlib import sha256

# Non-native imports
from Crypto.Cipher import AES

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c79-6d65726f-57617348-65726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions & Classes
class Database:
    def __init__(self, passkey: bytes):
        if isinstance(passkey, str):
            passkey = passkey.encode()
        self.key = sha256(b"::".join([b"KEY(_FLAG)", passkey, len(passkey).to_bytes(2, 'big')])).digest()
        self.uiv = int(sha256(b"::".join([b"UIV(_KEY)", self.key, len(self.key).to_bytes(2, 'big')])).hexdigest()[:24], 16)
        self.edb = {}
        print(f"{self.key = }")
        print(f"{self.uiv = }")
        t = int(time.time())
        x = (self.uiv).to_bytes(12, 'big')
        y = (self.uiv + t).to_bytes(12, 'big')
        print(f"{x = }")
        print(f"{y = }")

    def _GetUIV(self, f: str, l: int, t: int = 0) -> bytes:
        if not (0 < t < int(time.time())):
            t = int(time.time()); time.sleep(2)
        u = (self.uiv + t).to_bytes(12, 'big')
        v = sha256(b"::".join([b"UIV(_FILE)", f.encode(), l.to_bytes(2, 'big')])).digest()
        return t, bytes([i^j for i,j in zip(u, v)])

    def _Encrypt(self, f: str, x: bytes) -> bytes:
        if isinstance(x, str):
            x = x.encode()
        t, uiv = self._GetUIV(f, len(x))
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return t.to_bytes(4, 'big') + aes.encrypt(x)
    
    def _Decrypt(self, f: str, x: bytes) -> bytes:
        t, x = int.from_bytes(x[:4], 'big'), x[4:]
        _, uiv = self._GetUIV(f, len(x), t=t)
        aes = AES.new(self.key, AES.MODE_CTR, nonce=uiv)
        return aes.decrypt(x)
    
    def Insert(self, f, i, j):
        print(f"Inserting {f, i, j}")
        if isinstance(j, str):
            j = j.encode()
        if isinstance(j, int):
            j = j.to_bytes(-(-len(bin(j)[:2])//8), 'big')
        if f in self.edb:
            x = self._Decrypt(f, self.edb[f])
        else:
            x = b""
        y = x[:i] + j + x[i:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        print(f"{f = }")
        print(f"{x = }")
        print(f"{y = }")
        print(f"{z = }")
        print(f"{self.edb[f] = }")
        return z
        
    def Delete(self, f, i, j):
        if f not in self.edb:
            return b""
        x = self._Decrypt(f, self.edb[f])
        y = x[:i] + x[i+j:]
        z = self._Encrypt(f, y)
        self.edb[f] = z
        print(f"{f = }")
        print(f"{x = }")
        print(f"{y = }")
        print(f"{z = }")
        print(f"{self.edb[f] = }")
        return z


# Challenge set-up
HDR = """|
|   __________                __
|  |   _      |--.-----.-----|  |--.--.--.
|  |   |            -__   -__     <   |  |
|  |   |______|_________________|______  |
|  |   |   |                       |_____|
|  |       |
|  `-------'"""
print(HDR)

database = Database(FLAG)
database.Insert('flag', 0, FLAG)


# Server loop
TUI = "|\n|  Menu:\n|    [I]nsert\n|    [D]elete\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            raise KeyboardInterrupt

        elif choice == 'i':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'f', 'i', 'j'}
            ret = database.Insert(uin['f'], uin['i'], uin['j'])
            print("|  '{}' updated to 0x{}".format(uin['f'], ret.hex()))

        elif choice == 'd':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'f', 'i', 'j'}
            ret = database.Delete(uin['f'], uin['i'], uin['j'])
            print("|  '{}' updated to 0x{}".format(uin['f'], ret.hex()))

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))