import random
from ssbls12 import Fp, Poly, Group
from polynomial_evalrep import get_omega, polynomialsEvalRep
from setup import setup_algo
from verifier import verifier_algo
from circuit_setup import preprocess
from utils import *
import json
from ast import literal_eval

class PolySign:
    # Trusted setup
    def setup(self):
        print('Pls be patient...')
        message = input('Message: ')
        message = message.encode()
        if len(message) > 100 or len(message) < 3:
            print("Message too long or short")
            return

        wires, permutation, gates_matrix = preprocess(message)

        # Mundane stuff
        self.n = len(gates_matrix[0])
        n = self.n
        # seed = random.randint(0, entropy)
        message = list(message)

        L = list(range(len(message)))
        public_input = list(message)
        public_input = [Fp(x) for x in public_input]
        CRS, Qs, p_i_poly, perm_prep, verifier_prep = setup_algo(
            gates_matrix, permutation, L, public_input
        )
        self.perm_prep = perm_prep
        self.verifier_prep = verifier_prep

        res = json.dumps({
            'n': n,
            'perm_prep': [[repr(y) for y in x] if type(x) == list else repr(x) for x in perm_prep],
            'public_input': [int(x) for x in public_input],
            'CRS': [Group_to_hex(x) for x in CRS],
            'Qs': [repr(x) for x in Qs],
        })
        print('setup:', res)
        return res
        
    def verify_msg(self):
        signature = json.loads(input("Enter signature: "))
        msg, L, public_input, proof = (signature['msg'], signature['L'], signature['public_input'], signature['proof'])
        if len(msg) > 100 or len(msg) < 3:
            print("Too long or short")
            return
        
        msg = msg.encode()

        proof = literal_eval(proof)
        proof = convert_proof_elements(proof)
        assert all(x == y for x, y in zip(msg, public_input))

        # From setup.py
        n = self.n
        omega_base = get_omega(Fp, 2 ** 32, seed=0)
        omega = omega_base ** (2 ** 32 // n)
        omegas = [omega ** i for i in range(n)]
        PolyEvalRep = polynomialsEvalRep(Fp, omega, n)
        # The public input poly vanishes everywhere except for the position of the
        # public input gate where it evaluates to -(public_input)
        p_i = [Fp(0) for i in range(len(omegas))]
        for i, k in zip(L, public_input):
            p_i[i] = Fp(-k)
        p_i_poly = PolyEvalRep(omegas, p_i)
        

        verifier_algo(proof, n, p_i_poly, self.verifier_prep, self.perm_prep[2])

        print('Now you see me. Flag: DEAD{redact}')

ps = PolySign()
print("Welcome to PolySign!")
print("Create your NP signature!")

while True:
    ps.setup()

    ps.verify_msg()
