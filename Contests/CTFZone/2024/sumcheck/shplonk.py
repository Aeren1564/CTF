from ff import Fr
from transcript import ProverTranscript, VerifierTranscript, map_tuple_from_int_to_Fq
from dataclasses import dataclass
from py_ecc.optimized_bn128.optimized_curve import multiply, normalize, add, neg, Z1, G1
from py_ecc.fields import optimized_bn128_FQ
from polynomial import compute_quotient, batch_inverse, evaluate_polynomial
from kzg import KZG, convert_to_working_point


@dataclass
class ProverOpeningClaim:
    polynomial: list[Fr]
    x: Fr
    y: Fr


@dataclass
class VerifierOpeningClaim:
    commitment: tuple[optimized_bn128_FQ]
    x: Fr
    y: Fr


def compute_batched_quotient(claims: list[ProverOpeningClaim], batching_challenge):
    maximum_size = 0
    for claim in claims:
        maximum_size = max(maximum_size, len(claim.polynomial))
    result = compute_quotient(claims[0].polynomial, claims[0].x, claims[0].y)
    if len(result) < maximum_size:
        result.extend([Fr(0) for _ in range(maximum_size - len(result))])
    current_power = batching_challenge
    for i in range(1, len(claims)):
        sub_quotient = compute_quotient(claims[i].polynomial, claims[i].x, claims[i].y)
        for j in range(len(sub_quotient)):
            result[j] += sub_quotient[j] * current_power
        current_power *= batching_challenge
    return result


def compute_partially_evaluated_batched_quotient(
    claims: list[ProverOpeningClaim], batching_challenge, opening_challenge
):
    maximum_size = 0
    for claim in claims:
        maximum_size = max(maximum_size, len(claim.polynomial))
    inverse_preparation = [opening_challenge - claim.x for claim in claims]
    inverted = batch_inverse(inverse_preparation)
    result = [claims[0].polynomial[i] for i in range(len(claims[0].polynomial))]
    result[0] -= claims[0].y
    for i in range(len(result)):
        result[i] *= inverted[0]
    if len(result) < maximum_size:
        result.extend([Fr(0) for _ in range(maximum_size - len(result))])
    current_power = batching_challenge
    for i in range(1, len(claims)):
        multiplicand = current_power * inverted[i]
        for j in range(len(claims[i].polynomial)):
            if j != 0:
                result[j] += claims[i].polynomial[j] * multiplicand
            else:
                result[j] += (claims[i].polynomial[j] - claims[i].y) * multiplicand
        current_power *= batching_challenge
    return result


def compute_partially_evaluated_batched_quotient_commitment(
    claims: list[VerifierOpeningClaim], batching_challenge, opening_challenge
):
    inverse_preparation = [opening_challenge - claim.x for claim in claims]
    inverted = batch_inverse(inverse_preparation)
    result = Z1
    current_power = Fr(1)
    for i, claim in enumerate(claims):
        multiplicand = inverted[i] * current_power
        result = add(
            result,
            multiply(
                add(
                    convert_to_working_point(claim.commitment),
                    neg(multiply(G1, claim.y.value)),
                ),
                multiplicand.value,
            ),
        )
        current_power *= batching_challenge
    return result


class ShplonkProver:
    def __init__(
        self, opening_claims: list[ProverOpeningClaim], transcript: ProverTranscript
    ):
        self.opening_claims = opening_claims
        self.transcript = transcript
        self.kzg = KZG()

    def prove(self):
        shplonk_batching_challenge = self.transcript.get_challenge()

        batched_quotient = compute_batched_quotient(
            self.opening_claims, shplonk_batching_challenge
        )
        batched_quotient_commitment = self.kzg.commit(batched_quotient)
        self.transcript.send_to_verifier(
            map_tuple_from_int_to_Fq(batched_quotient_commitment)
        )
        shplonk_opening_challenge = self.transcript.get_challenge()
        partially_evaluated_quotient = compute_partially_evaluated_batched_quotient(
            self.opening_claims, shplonk_batching_challenge, shplonk_opening_challenge
        )
        difference = partially_evaluated_quotient
        for i, element in enumerate(batched_quotient):
            difference[i] -= element
        assert evaluate_polynomial(difference, shplonk_opening_challenge) == Fr(0)
        kzg_opening = self.kzg.open(difference, shplonk_opening_challenge)
        self.transcript.send_to_verifier(map_tuple_from_int_to_Fq(kzg_opening[2]))


class ShplonkVerifier:
    def __init__(
        self, opening_claims: list[VerifierOpeningClaim], transcript: VerifierTranscript
    ):
        self.opening_claims = opening_claims
        self.transcript = transcript
        self.kzg = KZG()

    def verify(self):
        shplonk_batching_challenge = self.transcript.get_challenge()
        quotient_commitment = convert_to_working_point(
            self.transcript.get_point_from_prover()
        )
        shplonk_opening_challenge = self.transcript.get_challenge()
        partially_opened_quotient_commitment = (
            compute_partially_evaluated_batched_quotient_commitment(
                self.opening_claims,
                shplonk_batching_challenge,
                shplonk_opening_challenge,
            )
        )
        final_commitment = add(
            partially_opened_quotient_commitment, neg(quotient_commitment)
        )
        opening_proof = self.transcript.get_point_from_prover()
        return self.kzg.verify(
            final_commitment,
            [shplonk_opening_challenge, Fr(0), convert_to_working_point(opening_proof)],
        )


import unittest
import random


class ShplonkTests(unittest.TestCase):
    def test_proof_correctness(self):
        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr(2))
        polynomial_1 = [Fr(0), Fr(2), Fr(0), Fr(0)]
        polynomial_2 = [Fr(0), Fr(1), Fr(0), Fr(0)]

        evaluation_point_1 = Fr(10)
        evaluation_point_2 = Fr(12)
        evaluation_1 = evaluate_polynomial(polynomial_1, evaluation_point_1)
        evaluation_2 = evaluate_polynomial(polynomial_2, evaluation_point_2)
        shplonk_prover = ShplonkProver(
            [
                ProverOpeningClaim(polynomial_1, evaluation_point_1, evaluation_1),
                ProverOpeningClaim(polynomial_2, evaluation_point_2, evaluation_2),
            ],
            prover_transcript,
        )
        shplonk_prover.prove()
        verifier_transcript = VerifierTranscript(prover_transcript.export_proof())
        verifier_transcript.get_Fr_from_prover()
        kzg = KZG()
        polynomial_1_commitment = kzg.commit(polynomial_1)
        polynomial_2_commitment = kzg.commit(polynomial_2)
        shplonk_verifier = ShplonkVerifier(
            [
                VerifierOpeningClaim(
                    polynomial_1_commitment, evaluation_point_1, evaluation_1
                ),
                VerifierOpeningClaim(
                    polynomial_2_commitment, evaluation_point_2, evaluation_2
                ),
            ],
            verifier_transcript,
        )

        self.assertTrue(shplonk_verifier.verify())

    def test_proof_correctness_random_polynomials(self):
        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr.from_bytes(random.randbytes(32)))
        polynomial_1 = [Fr.from_bytes(random.randbytes(32)) for i in range(16)]
        polynomial_2 = [Fr.from_bytes(random.randbytes(32)) for i in range(16)]
        polynomial_3 = [Fr.from_bytes(random.randbytes(32)) for i in range(16)]

        evaluation_point_1 = Fr.from_bytes(random.randbytes(32))
        evaluation_point_2 = Fr.from_bytes(random.randbytes(32))
        evaluation_point_3 = Fr.from_bytes(random.randbytes(32))
        evaluation_1 = evaluate_polynomial(polynomial_1, evaluation_point_1)
        evaluation_2 = evaluate_polynomial(polynomial_2, evaluation_point_2)
        evaluation_3 = evaluate_polynomial(polynomial_3, evaluation_point_3)
        shplonk_prover = ShplonkProver(
            [
                ProverOpeningClaim(polynomial_1, evaluation_point_1, evaluation_1),
                ProverOpeningClaim(polynomial_2, evaluation_point_2, evaluation_2),
                ProverOpeningClaim(polynomial_3, evaluation_point_3, evaluation_3),
            ],
            prover_transcript,
        )
        shplonk_prover.prove()
        verifier_transcript = VerifierTranscript(prover_transcript.export_proof())
        verifier_transcript.get_Fr_from_prover()
        kzg = KZG()
        polynomial_1_commitment = kzg.commit(polynomial_1)
        polynomial_2_commitment = kzg.commit(polynomial_2)
        polynomial_3_commitment = kzg.commit(polynomial_3)
        shplonk_verifier = ShplonkVerifier(
            [
                VerifierOpeningClaim(
                    polynomial_1_commitment, evaluation_point_1, evaluation_1
                ),
                VerifierOpeningClaim(
                    polynomial_2_commitment, evaluation_point_2, evaluation_2
                ),
                VerifierOpeningClaim(
                    polynomial_3_commitment, evaluation_point_3, evaluation_3
                ),
            ],
            verifier_transcript,
        )

        self.assertTrue(shplonk_verifier.verify())


if __name__ == "__main__":
    unittest.main()
