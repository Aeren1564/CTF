from circuit import CircuitBuilder
from ff import Fr
from uint import Uint8
import unittest
from prover import Prover, Verifier


def standard_xor_example():
    cb = CircuitBuilder()
    left = [Uint8(cb, x) for x in b"\xc0\x00\xff\xee"]
    right = [Uint8(cb, x) for x in b"\xde\xad\xbe\xef"]
    for x in left:
        x.fix_witness()
    for x in right:
        x.fix_witness()
    for x, y in zip(left, right):
        (x ^ y).fix_witness()

    Uint8(cb, 0) ^ Uint8(cb, 1)
    Uint8(cb, 0) ^ Uint8(cb, 1)
    Uint8(cb, 0) ^ Uint8(cb, 1)
    return cb


def impossible_xor_example():
    cb = CircuitBuilder()
    left = [Uint8(cb, x) for x in b"\xc0\x00\xff\xee"]
    right = [Uint8(cb, x) for x in b"\xde\xad\xbe\xef"]
    for x in left:
        x.fix_witness()
    for x in right:
        x.fix_witness()
    for x, y in zip(left, right):
        result = x ^ y
        cb.connect(cb.zero_index, result.witness_index, False)

    Uint8(cb, 0) ^ Uint8(cb, 1)
    Uint8(cb, 0) ^ Uint8(cb, 1)
    Uint8(cb, 0) ^ Uint8(cb, 1)
    return cb


class TestStandard(unittest.TestCase):
    def test_standard(self):
        cb = standard_xor_example()
        prover = Prover(cb)
        prover.prove()
        self.assertTrue(Verifier(prover.export_proof()).verify())

    # def test_broken(self):
    #     cb = impossible_xor_example()
    #     prover = Prover(cb)
    #     prover.prove()
    #     self.assertFalse(Verifier(prover.export_proof()).verify())


if __name__ == "__main__":
    cb = standard_xor_example()
    prover = Prover(cb)
    standard_xor_vk = prover.generate_verification_key()
    prover.prove()
    standard_xor_proof = prover.export_proof()
    cb = impossible_xor_example()
    prover = Prover(cb, disable_lookup_multiplicity_computation=True)
    impossible_xor_vk = prover.generate_verification_key()
    with open("standard_xor.vk", "wb") as f:
        f.write(standard_xor_vk.hex().encode())
    with open("impossible_xor.vk", "wb") as f:
        f.write(impossible_xor_vk.hex().encode())
    with open("standard_xor.proof", "w") as f:
        f.write(standard_xor_proof.hex())
