import json, os, sys
from pathlib import Path
from sage.all import *
import mceliece


import subprocess,json



pk = json.loads(Path("data/pubkey").read_text())

H, w = pk["P"], pk["w"]
n = len(H[0])
k = n-len(H)

syndrome = json.loads(Path("data/secret.txt.enc").read_text())
MCELIECE_PARAMS = (3488, 64, 12)

flag = os.getenv("FLAG", "flag{testflag}")

def ask_weights():
    print("Enter the error:")
    try:
        datafile = json.loads(input())
    except EOFError:
        return


    # check length 
    if len(datafile) != MCELIECE_PARAMS[0]:
        print("wrong len")
        return
        # check if binary
    if not all([0 <= d <= 1 for d in datafile]):
        print("not binary")
        return

    # check weight:
    weight = sum(datafile)
    if weight < w:
        print("wrong weight %d" % weight)
        return

    # compute syndrome
    check_syndrome = None
    try:
        data = vector(GF(2), datafile)
        check_syndrome = mceliece.encrypt([matrix(GF(2), pk["P"]), pk["w"]], data)
    except e as Exception:
        print(e)
        return
    
    # check syndrome
    for i in range(n-k):
        if syndrome[i] != check_syndrome[i]:
            print("wrong syndrome")
            return
    print(flag)
    exit(0)
    

def main():
    print("Welcome to McEliece Weight Lifting!")
    print("Robert, our lord and savior of the gym, reveals his flag only after you lift some weights.")
    while True:
        ask_weights()

if __name__ == '__main__':
    try:
        main()
    except EOFError:
        pass
    except KeyboardInterrupt:
        pass
