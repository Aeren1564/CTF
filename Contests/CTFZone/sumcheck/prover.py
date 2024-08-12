from instance import (
    Instance,
    NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
    NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
)
from circuit import CircuitBuilder
from polynomial import evaluate_polynomial
from relations import RelationChallenges
from transcript import ProverTranscript, VerifierTranscript, map_tuple_from_int_to_Fq
from ff import Fr, Fq
from kzg import KZG
from gemini import GeminiProver, GeminiVerifier
import unittest
from uint import Uint8
from sumcheck import SumcheckProver, SumcheckVerifier, SumcheckChallenges
from shplonk import ShplonkProver, ShplonkVerifier


class Prover:

    def __init__(
        self, cb: CircuitBuilder, disable_lookup_multiplicity_computation=False
    ):
        self.instance = Instance(cb, disable_lookup_multiplicity_computation)
        self.kzg = KZG()
        self.transcript = ProverTranscript()

    def generate_verification_key(self):
        self.transcript = ProverTranscript()
        self.transcript.send_to_verifier(self.instance.instance_size)
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )
        vk = self.transcript.export_proof()
        self.transcript = ProverTranscript()
        return vk

    def prove(self, before_sumcheck_update=lambda x: None):
        # VK data

        # Round 0

        # Send verification key part

        self.transcript.send_to_verifier(self.instance.instance_size)
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )

        # Round 1

        for i in range(
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
            + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
        ):
            self.transcript.send_to_verifier(
                map_tuple_from_int_to_Fq(
                    self.kzg.commit(self.instance.all_polynomials[i])
                )
            )

        beta_challenge = self.transcript.get_challenge()
        self.beta_challenge = beta_challenge
        gamma_challenge = self.transcript.get_challenge()
        self.gamma_challenge = gamma_challenge

        self.instance.generate_permutation_polynomial(beta_challenge, gamma_challenge)
        self.instance.generate_logup_inverse_polynomial(beta_challenge, gamma_challenge)

        self.transcript.send_to_verifier(
            map_tuple_from_int_to_Fq(
                self.kzg.commit(self.instance.all_polynomials.permutation)
            )
        )

        zeta_challenge = self.transcript.get_challenge()
        self.zeta_challenge = zeta_challenge

        self.instance.generate_zeta_power_polynomial(zeta_challenge)

        before_sumcheck_update(self)

        sumcheck_challenges = SumcheckChallenges(zeta_challenge)

        relation_challenges = RelationChallenges(beta_challenge, gamma_challenge)
        sumcheck_prover = SumcheckProver(
            self.instance, self.transcript, sumcheck_challenges, relation_challenges
        )

        evaluation_point = sumcheck_prover.prove()

        gemini_prover = GeminiProver(
            list(
                [
                    self.instance.all_polynomials[i]
                    for i in range(
                        NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
                        + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS
                    )
                ]
                + [self.instance.all_polynomials.permutation]
            ),
            [
                self.instance.all_polynomials.permutation,
                self.instance.all_polynomials.w_l,
                self.instance.all_polynomials.w_r,
                self.instance.all_polynomials.w_o,
            ],
            self.transcript,
            evaluation_point,
        )

        opening_claims = gemini_prover.prove()

        shplonk_prover = ShplonkProver(opening_claims, self.transcript)
        shplonk_prover.prove()

    def export_proof(self):
        return self.transcript.export_proof()


class Verifier:
    def __init__(self, proof_data: bytes):
        self.transcript = VerifierTranscript(proof_data)

    def verify(self, verification_key=bytes([])):

        # Round 0
        self.instance_size = self.transcript.get_int_from_prover()
        # Get VK data
        vk_commitments = []
        for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
            vk_commitments.append(self.transcript.get_point_from_prover())

        if len(verification_key) != 0:
            vk_transcript = VerifierTranscript(verification_key)
            vk_instance_size = vk_transcript.get_int_from_prover()
            if vk_instance_size != self.instance_size:
                return False
            for i in range(NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS):
                if vk_commitments[i] != vk_transcript.get_point_from_prover():
                    print("Verification Key Discrepancy")
                    return False

        initial_witness_commitments = []
        for i in range(
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS,
            NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
            + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS,
        ):
            initial_witness_commitments.append(self.transcript.get_point_from_prover())

        beta_challenge = self.transcript.get_challenge()
        gamma_challenge = self.transcript.get_challenge()

        permutation_commitment = self.transcript.get_point_from_prover()

        zeta_challenge = self.transcript.get_challenge()

        sumcheck_challenges = SumcheckChallenges(zeta_challenge)

        relation_challenges = RelationChallenges(beta_challenge, gamma_challenge)

        sumcheck_verifier = SumcheckVerifier(
            self.instance_size,
            self.transcript,
            sumcheck_challenges,
            relation_challenges,
        )

        (sumcheck_verified, evaluation_point, polynomial_evaluations) = (
            sumcheck_verifier.verify()
        )
        if not sumcheck_verified:
            print("Sumcheck failed")
            return False
        gemini_verifier = GeminiVerifier(
            vk_commitments + initial_witness_commitments + [permutation_commitment],
            [
                permutation_commitment,
                initial_witness_commitments[0],
                initial_witness_commitments[1],
                initial_witness_commitments[2],
            ],
            self.transcript,
            evaluation_point,
            list(
                [
                    polynomial_evaluations[i][0]
                    for i in range(
                        NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS
                        + NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS
                    )
                ]
                + [
                    polynomial_evaluations.permutation[0],
                    polynomial_evaluations.permutation_shift[0],
                    polynomial_evaluations.w_l_shift[0],
                    polynomial_evaluations.w_r_shift[0],
                    polynomial_evaluations.w_o_shift[0],
                ]
            ),
        )

        (gemini_verified, verifier_opening_claims) = gemini_verifier.verify()

        if not gemini_verified:
            print("Gemini failed")
            return False

        shplonk_verifier = ShplonkVerifier(verifier_opening_claims, self.transcript)

        result = shplonk_verifier.verify()

        return result


class TestProver(unittest.TestCase):
    def test_full_proof_with_vk(self):
        cb = CircuitBuilder()
        a = Uint8(cb, 0xFF)
        b = Uint8(cb, 0xF)
        d = a ^ b
        prover = Prover(cb)
        verification_key = prover.generate_verification_key()
        prover.prove()
        proof = prover.export_proof()
        verfier = Verifier(proof)
        self.assertTrue(verfier.verify(verification_key=verification_key))


if __name__ == "__main__":
    unittest.main()
