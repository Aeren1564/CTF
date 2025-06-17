#!/usr/local/bin/python
import json
from Verifier import Verifier
from compression import decompress
from merkletree import MerkleTree
from fft import fft

v = Verifier()
max_degree = 0

proof = json.loads(decompress(input("gimme your proof: ")).decode())
if not v.verify(proof["last_comm"], proof["roots"], proof["queries"], max_degree):
    print("Proof is invalid")
    exit(1)


#poly = [int(x)%v.p for x in decompress(input("gimme your polynomial: ")).decode().split(",")]
poly = [v.domain_length+1337+i for i in range(v.domain_length)] # :3

evals = fft(poly, v.ω, v.p)
root = MerkleTree(evals).get_root()
if root != proof["roots"][0]:
    print("Polynomial does not match the proof")
    exit(1)

print(f"...")
print(open("flag.txt").read())
