from ff import FF, Fr, Fq, FF_BYTE_LENGTH
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import blake2b
import random
import unittest
from kzg import convert_to_working_point

b = Fq(3)

DOMAIN_SEPARATION_SALT = b"CTFZONE_2024!"


def map_tuple_from_int_to_Fq(elements):
    return tuple(map(Fq, [x if type(x) == int else x.n for x in elements]))


def map_tuple_from_Fq_into_int(elements):
    return tuple(map(int, [x if type(x) == int else x.value for x in elements]))


class ProverTranscript:

    def __init__(self):
        self.data_bytes = []
        self.round_challenge_index = 0

    def send_to_verifier(self, element):
        self.round_challenge_index = 0
        if type(element) == Fr or type(element) == Fq or type(element) == FF:
            self.data_bytes.extend(element.to_bytes())
        elif type(element) == int:
            assert element < (1 << 32)
            self.data_bytes.extend(long_to_bytes(element, 4))
        elif type(element) == tuple:
            for sub_element in element:
                self.send_to_verifier(sub_element)
        else:
            raise Exception("WTF" + str(type(element)))

    def get_challenge(self):
        if len(self.data_bytes) == 0:
            raise Exception("Not data to FS yet")
        buffer = bytes(self.data_bytes) + long_to_bytes(self.round_challenge_index, 2)
        result_bytes = blake2b(buffer, salt=DOMAIN_SEPARATION_SALT).digest()
        self.round_challenge_index += 1
        return Fr(bytes_to_long(result_bytes))

    def export_proof(self):
        return bytes(self.data_bytes)


class VerifierTranscript:
    def __init__(self, proof_data: bytes):
        self.proof_data = proof_data
        self.offset = 0
        self.round_challenge_index = 0

    def get_Fr_from_prover(self):
        assert len(self.proof_data) - self.offset >= FF_BYTE_LENGTH
        chunk = self.proof_data[self.offset : self.offset + FF_BYTE_LENGTH]
        self.offset += FF_BYTE_LENGTH
        self.round_challenge_index = 0
        return Fr.from_bytes(chunk)

    def get_Fq_from_prover(self):
        assert len(self.proof_data) - self.offset >= FF_BYTE_LENGTH
        chunk = self.proof_data[self.offset : self.offset + FF_BYTE_LENGTH]
        self.offset += FF_BYTE_LENGTH
        self.round_challenge_index = 0
        return Fq.from_bytes(chunk)

    def get_point_from_prover(self):
        point = (self.get_Fq_from_prover(), self.get_Fq_from_prover())
        (x, y) = point
        assert y * y == (x * x) * x + b or (y == Fq(0) and x == Fq(0))
        return point

    def get_int_from_prover(self):
        assert len(self.proof_data) - self.offset >= 4
        chunk = self.proof_data[self.offset : self.offset + 4]
        self.offset += 4
        self.round_challenge_index = 0
        return bytes_to_long(chunk)

    def get_challenge(self):
        if self.offset == 0:
            raise Exception("Not data to FS yet")
        buffer = self.proof_data[: self.offset] + long_to_bytes(
            self.round_challenge_index, 2
        )
        result_bytes = blake2b(buffer, salt=DOMAIN_SEPARATION_SALT).digest()
        self.round_challenge_index += 1
        return Fr.from_bytes(result_bytes)


class TestTranscript(unittest.TestCase):
    def test_prover_transcript(self):
        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fq(1))
        challenge_0 = prover_transcript.get_challenge()
        prover_transcript.send_to_verifier(Fq(1))
        challenge_1 = prover_transcript.get_challenge()
        challenge_2 = prover_transcript.get_challenge()
        self.assertNotEqual(challenge_1, challenge_0)
        self.assertNotEqual(challenge_2, challenge_1)
        prover_transcript1 = ProverTranscript()
        prover_transcript1.send_to_verifier(Fq(2))
        challenge_0_1 = prover_transcript.get_challenge()
        self.assertNotEqual(challenge_0, challenge_0_1)

    def test_prover_verifier_transcript_equivalence(self):

        first_element = Fr.from_bytes(random.randbytes(FF_BYTE_LENGTH * 2))
        second_element = Fq.from_bytes(random.randbytes(FF_BYTE_LENGTH * 2))
        element_tuple = (
            Fq.from_bytes(random.randbytes(FF_BYTE_LENGTH * 2)),
            Fr.from_bytes(random.randbytes(FF_BYTE_LENGTH * 2)),
        )

        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(first_element)
        prover_challenge_0 = prover_transcript.get_challenge()
        prover_transcript.send_to_verifier(second_element)
        prover_challenge_1 = prover_transcript.get_challenge()
        prover_transcript.send_to_verifier(element_tuple)
        prover_challenge_2 = prover_transcript.get_challenge()
        prover_challenge_3 = prover_transcript.get_challenge()

        proof_data = prover_transcript.export_proof()

        verifier_transcript = VerifierTranscript(proof_data)

        first_verifier_element = verifier_transcript.get_Fr_from_prover()
        verifier_challenge_0 = verifier_transcript.get_challenge()
        second_verifier_element = verifier_transcript.get_Fq_from_prover()
        verifier_challenge_1 = verifier_transcript.get_challenge()
        verifier_element_tuple = (
            verifier_transcript.get_Fq_from_prover(),
            verifier_transcript.get_Fr_from_prover(),
        )
        verifier_challenge_2 = verifier_transcript.get_challenge()
        verifier_challenge_3 = verifier_transcript.get_challenge()
        self.assertEqual(first_element, first_verifier_element)
        self.assertEqual(second_element, second_verifier_element)
        self.assertEqual(element_tuple[0], verifier_element_tuple[0])
        self.assertEqual(element_tuple[1], verifier_element_tuple[1])
        self.assertEqual(verifier_challenge_0, prover_challenge_0)
        self.assertEqual(verifier_challenge_1, prover_challenge_1)
        self.assertEqual(verifier_challenge_2, prover_challenge_2)
        self.assertEqual(verifier_challenge_3, prover_challenge_3)


if __name__ == "__main__":
    unittest.main()
