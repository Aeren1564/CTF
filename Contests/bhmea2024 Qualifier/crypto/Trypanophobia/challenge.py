#!/usr/bin/env python3
#
# BlackHat MEA 2024 CTF Qualifiers
#
# [Easy] Crypto - Trypanophobia
#

# Native imports
import os, json, hashlib

# Non-native imports
from Crypto.Util.number import getPrime, isPrime, inverse, GCD     # pip install pycryptodome

# Flag import
FLAG = os.environ.get('DYN_FLAG', 'BHFlagY{506f6c796d65726f5761734865726521}')
if isinstance(FLAG, str):
    FLAG = FLAG.encode()


# Functions & Classes
class RSAKey:
    def __init__(self):
        self.public = None
        self.private = None
        
    @staticmethod
    def new():
        p = getPrime(1024)
        while True:
            q = getPrime(1024)
            f = (p - 1) * (q - 1)
            if GCD(f, 0x10001) == 1:
                break
        key = RSAKey()
        key.public = {
            'e' : 0x10001
        }
        key.private = {
            'p' : [p, q]
        }
        key.update()
        return key
    
    def update(self):
        self.public['n'] = 1
        self.private['f'] = 1
        for p in self.private['p']:
            self.public['n'] *= p
            self.private['f'] *= (p - 1)
        self.private['d'] = inverse(self.public['e'], self.private['f'])

    def pad(self, x):
        y = int(hashlib.sha256(str(set(self.private['p'])).encode()).hexdigest(), 16)
        while x < self.public['n']:
            x *= y
        x //= y
        return x
        
    def encrypt(self, x):
        if 0 < x < self.public['n']:
            return pow(self.pad(x), self.public['e'], self.public['n'])
        else:
            return 0


# Challenge set-up
HDR = """|
|  ┏┳┓              ┓   ┓ •
|   ┃ ┏┓┓┏┏┓┏┓┏┓┏┓┏┓┣┓┏┓┣┓┓┏┓
|   ┻ ┛ ┗┫┣┛┗┻┛┗┗┛┣┛┛┗┗┛┗┛┗┗┻
|        ┛┛       ┛"""
print(HDR)

ourKey = RSAKey.new()


# Server loop
TUI = "|\n|  Menu:\n|    [A]dd a key\n|    [E]ncrypt flag\n|    [Q]uit\n|"

while True:
    try:

        print(TUI)
        choice = input("|  > ").lower()

        if choice == 'q':
            print('|\n|  [~] Goodbye ~ !\n|')
            break
        
        elif choice == 'a':
            uin = json.loads(input("|  > (JSON) "))
            assert uin.keys() == {'p', 'q'}
            if all([
                isPrime(uin['p']), isPrime(uin['q']),
                len(bin(uin['p'])) == 1024 + 2,
                len(bin(uin['q'])) == 1024 + 2
            ]):
                ourKey.private['p'] += [uin['p'], uin['q']]
                ourKey.update()
            else:
                print('|  [!] Invalid primes.')

        elif choice == 'e':
            enc = ourKey.encrypt(int.from_bytes(FLAG, 'big'))
            print('|  Flag = 0x{:x}'.format(enc))

        else:
            print('|  [!] Invalid choice.')

    except KeyboardInterrupt:
        print('\n|\n|  [~] Goodbye ~ !\n|')
        break

    except Exception as e:
        print('|  [!] ERROR :: {}'.format(e))