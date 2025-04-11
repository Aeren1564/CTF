import os
import secrets
import signal
from Crypto.Hash import SHA256
from Crypto.Util.number import getPrime, isPrime, long_to_bytes


class LCG:
    def __init__(self, m: int):
        self.m = m
        self.a, self.b, self.x = (
            secrets.randbelow(m),
            secrets.randbelow(m),
            secrets.randbelow(m),
        )

    def next(self):
        self.x = (self.a * self.x + self.b) % self.m
        return self.x


class SchnorrSignature:
    def __init__(self):
        self.p = 1
        while not isPrime(self.p):
            self.q = getPrime(384)
            self.p = self.q * 2 + 1
        self.g = 2**2

        self.rng = LCG(self.q)
        self.priv_key = secrets.randbelow(self.q - 1) + 1
        self.pub_key = pow(self.g, self.priv_key, self.p)

    def pub(self):
        return self.p, self.g, self.pub_key

    def sign(self, message: bytes):
        k = self.rng.next()  # k ∈ {0, 1, 2, ..., q-1}
        r = pow(self.g, k, self.p)  # r = g^k mod p
        e = self._hash(message, r)  # e = H(m || r)
        s = (k + self.priv_key * e) % self.q  # s = (k + x * e) mod q
        return (e, s)

    def verify(self, message: bytes, e: int, s: int):
        if not (0 <= e < self.q): return False
        if not (0 <= s < self.q): return False
        # Compute r' = g^s * y^{-e} mod p
        r_prime = (pow(self.g, s, self.p) * pow(self.pub_key, -e, self.p)) % self.p
        # Compute e' = H(m || r')
        e_prime = self._hash(message, r_prime)
        # Signature is valid if e == e'
        return e == e_prime

    def _hash(self, message: bytes, r: int):
        hash_res = SHA256.new(message + long_to_bytes(r))
        return int(hash_res.hexdigest(), 16) % self.q


FLAG = os.environ.get("FLAG", "fakeflag")

WELCOME = """
1: sign
2: verify
""".strip()

GIVE_ME_FLAG = b"give me flag"


def main():
    print("[+] generating keys...")
    schnorr_signature = SchnorrSignature()
    p, g, pub_key = schnorr_signature.pub()
    signal.alarm(300)
    print(f"{p=}\n{g=}\n{pub_key=}")
    print("1: sign\n2: verify")
    while True:
        option = int(input("option> "))
        if option == 1:
            message = bytes.fromhex(input("message(in hex)> "))
            if message == GIVE_ME_FLAG:
                print("nope")
                continue
            e, s = schnorr_signature.sign(message)
            print(f"{e=}")
            print(f"{s=}")
            continue

        if option == 2:
            message = bytes.fromhex(input("message(in hex)> "))
            e = int(input("e> "))
            s = int(input("s> "))
            if not schnorr_signature.verify(message, e, s):
                print("Verification failed")
                continue
            print("Verification success!")
            if message == GIVE_ME_FLAG:
                print("Here is your flag:", FLAG)
            continue

        print("invalid option")


if __name__ == "__main__":
    main()
