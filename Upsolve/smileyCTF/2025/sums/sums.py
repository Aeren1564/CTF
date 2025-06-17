#!/usr/local/bin/python
from IPVerifier import InteractiveVerifier
from IPProverLinear import InteractiveLinearProver
from polynomial import randomMVLinear
from random import randint
P = 2**256 - 189
NUM_VARS = 10
seed = randint(0, 2**64)
tries = 3
verifier = InteractiveVerifier(seed, randomMVLinear(10, P), 0)
def prime_verifier(poly, s_claim):
    global verifier
    verifier.poly = poly
    verifier.asserted_sum = s_claim % P
    verifier.active = True
    verifier.convinced = False
    verifier.round = 0
    verifier.expect = s_claim % P

def random_poly():
    poly = randomMVLinear(10, P)
    return poly


def do_run():
    global tries
    poly = random_poly()
    while (s_actual:=InteractiveLinearProver(poly).calculateTable()[1]) == 1337:
        poly = random_poly()
    print("Polynomial: ", poly.terms)
    s_claim = int(input("Enter the sum: "))
    prime_verifier(poly, s_claim)
    p0 = int(input("Enter P(0): ")) % P
    p1 = int(input("Enter P(1): ")) % P
    res = verifier.talk(p0, p1)
    if not res[0]:
        print("CHEATER!")
        return False
    print("Your odds: ", verifier.soundnessError())
    play = input("Do you want to play? (y/n): ")
    if play != "y":
        print("Bye")
        return False
    tries -= 1
    while verifier.active:
        print(f"challenge: {res}")
        p0 = int(input("Enter P(0): ")) % P
        p1 = int(input("Enter P(1): ")) % P
        res = verifier.talk(p0, p1)
        if not res[0]:
            print("CHEATER!")
            return False
    if not verifier.convinced:
        return False
    
    if s_claim != s_actual and s_claim == 1337:
        print("Wow...")
        return True
    return False # congrats, you played and lost...

def main():
    while tries:
        if do_run():
            print("Hmm, you won my game?")
            print("Flag: " + open("flag.txt", "r").read())
            break
        else:
            print("Skissue + get good")
            print("You have {} tries left".format(tries))
    


if __name__ == "__main__":
    main()
