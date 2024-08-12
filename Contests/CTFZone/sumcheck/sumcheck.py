from instance import AllPolynomials, Instance, NUMBER_OF_POLYNOMIALS
from relations import (
    ArithmeticRelation,
    PermutationConsequentRelationNoPublicInputs,
    PermutationRelationLastElement,
    LookupMainRelation,
    LookupInverseCorrectness,
    RelationChallenges,
)
from transcript import ProverTranscript, VerifierTranscript
from copy import deepcopy
import unittest
from ff import Fr
from ff_ct import Fr_ct
from collections import namedtuple
from polynomial import (
    partially_evaluate_multilinear_polynomial,
    convert_from_lagrange_to_monomial_form,
    evaluate_polynomial,
    batch_polynomials,
)

SumcheckChallenges = namedtuple("SumcheckChallenges", ["zeta"], defaults=[Fr(-1)])


def evaluate_multilinear_zeta_power_polynomial(challenges, zeta):
    result = Fr(1)
    current_power = zeta
    for challenge in challenges:
        difference = current_power - Fr(1)
        result *= Fr(1) + challenge * difference
        current_power *= current_power
    return result


def take_cube_edges(round_polynomials: AllPolynomials, index: int):
    edges = AllPolynomials(*([[] for _ in range(NUMBER_OF_POLYNOMIALS)]))
    for round_polynomial, edge in zip(round_polynomials, edges):
        edge.append(round_polynomial[index * 2])
        edge.append(round_polynomial[index * 2 + 1])
    return edges


def extend_edges(edges: AllPolynomials, length: int):
    extended_edges = AllPolynomials(*([[] for _ in range(NUMBER_OF_POLYNOMIALS)]))
    for edge, extended_edge in zip(edges, extended_edges):
        difference = edge[1] - edge[0]
        for i in range(2):
            extended_edge.append(edge[i])
        for i in range(2, length):
            extended_edge.append(extended_edge[i - 1] + difference)
    return extended_edges


def partially_evaluate_all_polynomials(
    round_polynomials: AllPolynomials, challenge: Fr
):
    round_length = len(round_polynomials[0])
    assert round_length >= 2 and round_length % 2 == 0
    new_round_polynomials = AllPolynomials(
        *([[] for _ in range(NUMBER_OF_POLYNOMIALS)])
    )
    for old_polynomial, new_polynomial in zip(round_polynomials, new_round_polynomials):
        new_polynomial.extend(
            partially_evaluate_multilinear_polynomial(old_polynomial, challenge)
        )
    return new_round_polynomials


class SumcheckProver:
    def __init__(
        self,
        instance: Instance,
        transcript: ProverTranscript,
        sumcheck_challenges: SumcheckChallenges,
        relation_challenges: RelationChallenges,
    ):
        self.transcript = transcript
        self.sumcheck_challenges = sumcheck_challenges
        self.instance = instance
        self.currentPolynomials = deepcopy(instance.all_polynomials)
        self.full_domain_relations = [LookupMainRelation(relation_challenges)]
        self.per_row_relations = [
            ArithmeticRelation(relation_challenges),
            PermutationConsequentRelationNoPublicInputs(relation_challenges),
            PermutationRelationLastElement(relation_challenges),
        ]
        self.separate_relation = LookupInverseCorrectness(relation_challenges)
        max_power = 0
        for relation in self.per_row_relations:
            max_power = max(max_power, relation.get_power())
        self.extended_length = max_power + 2  # 1 for power -> coeff  + 1 for zeta
        self.round_challenges = []

    def prove_round(self):

        round_size = len(self.currentPolynomials[0])
        assert round_size > 1
        result = [Fr(0) for _ in range(self.extended_length)]
        per_row_relations_alpha_power = self.alpha.pow(len(self.full_domain_relations))
        logup_result = [Fr(0) for _ in range(self.extended_length)]
        for i in range(0, round_size // 2):
            # Take edges
            edges = take_cube_edges(self.currentPolynomials, i)
            extended_edges = extend_edges(edges, self.extended_length)

            # Evaluate relations
            full_domain_relations_results = [
                relation.evaluate(extended_edges)
                for relation in self.full_domain_relations
            ]

            per_row_relations_results = [
                relation.evaluate(extended_edges) for relation in self.per_row_relations
            ]

            batched_full_domain_relations_results = batch_polynomials(
                full_domain_relations_results,
                self.alpha,
            )

            batched_per_row_relations_results = batch_polynomials(
                per_row_relations_results, self.alpha, per_row_relations_alpha_power
            )
            for j in range(self.extended_length):
                result[j] += batched_full_domain_relations_results[j] + (
                    batched_per_row_relations_results[j] * extended_edges.zeta_powers[j]
                )

            # Separate logup relation
            logup_at_edge = self.separate_relation.evaluate(extended_edges)
            for j in range(self.extended_length):
                logup_result[j] += logup_at_edge[j] * extended_edges.zeta_powers[j]

        for element in result:
            self.transcript.send_to_verifier(element)
        # Send logup relation results
        for element in logup_result:
            self.transcript.send_to_verifier(element)
        sumcheck_round_challenge = self.transcript.get_challenge()
        self.round_challenges.append(sumcheck_round_challenge)
        self.currentPolynomials = partially_evaluate_all_polynomials(
            self.currentPolynomials, sumcheck_round_challenge
        )

    def prove(self):
        self.alpha = self.transcript.get_challenge()
        instance_size = len(self.currentPolynomials[0])
        for i in range(instance_size.bit_length() - 1):
            self.prove_round()

        assert len(self.currentPolynomials[0]) == 1
        for i, multilinear_polynomial_evaluation in enumerate(self.currentPolynomials):
            self.transcript.send_to_verifier(multilinear_polynomial_evaluation[0])
        return self.round_challenges


class SumcheckVerifier:
    def __init__(
        self,
        instance_size: int,
        transcript: VerifierTranscript,
        challenges: SumcheckChallenges,
        relation_challenges: RelationChallenges,
    ):
        self.transcript = transcript
        self.sumcheck_challenges = challenges

        self.full_domain_relations = [LookupMainRelation(relation_challenges)]
        self.per_row_relations = [
            ArithmeticRelation(relation_challenges),
            PermutationConsequentRelationNoPublicInputs(relation_challenges),
            PermutationRelationLastElement(relation_challenges),
        ]
        self.separate_relation = LookupInverseCorrectness(relation_challenges)
        self.target_sum = Fr(0)
        self.logup_correctness_target_sum = Fr(0)
        self.instance_size = instance_size
        max_power = 0
        for relation in self.per_row_relations:
            max_power = max(max_power, relation.get_power())
        self.extended_length = max_power + 2
        self.round_challenges = []

    def verify_round(self) -> bool:
        round_univariate = []
        logup_correctness_round_univariate = []
        for i in range(self.extended_length):
            round_univariate.append(self.transcript.get_Fr_from_prover())

        for i in range(self.extended_length):
            logup_correctness_round_univariate.append(
                self.transcript.get_Fr_from_prover()
            )

        if round_univariate[0] + round_univariate[1] != self.target_sum:
            return False
        if (
            logup_correctness_round_univariate[0]
            + logup_correctness_round_univariate[1]
            != self.logup_correctness_target_sum
        ):
            return False
        round_challenge = self.transcript.get_challenge()

        self.round_challenges.append(round_challenge)

        monomial = convert_from_lagrange_to_monomial_form(round_univariate)

        monomial_at_challenge = evaluate_polynomial(monomial, round_challenge)

        self.target_sum = monomial_at_challenge

        logup_monomial = convert_from_lagrange_to_monomial_form(
            logup_correctness_round_univariate
        )

        logup_monomial_at_challenge = evaluate_polynomial(
            logup_monomial, round_challenge
        )

        self.logup_correctness_target_sum = logup_monomial_at_challenge

        return True

    def verify(self):
        self.alpha = self.transcript.get_challenge()

        per_row_relations_alpha_power = self.alpha.pow(len(self.full_domain_relations))
        for i in range(self.instance_size.bit_length() - 1):
            round_result = self.verify_round()
            if not round_result:
                return (False, Fr(0), [])
        polynomial_evaluations = AllPolynomials(
            *(
                [
                    [self.transcript.get_Fr_from_prover()]
                    for _ in range(NUMBER_OF_POLYNOMIALS)
                ]
            )
        )

        batched_full_domain_relations_result = batch_polynomials(
            [
                relation.evaluate(polynomial_evaluations)
                for relation in self.full_domain_relations
            ],
            self.alpha,
        )
        batched_per_row_relations_result = batch_polynomials(
            [
                relation.evaluate(polynomial_evaluations)
                for relation in self.per_row_relations
            ],
            self.alpha,
            per_row_relations_alpha_power,
        )
        full_sum = (
            batched_full_domain_relations_result[0]
            + batched_per_row_relations_result[0]
            * polynomial_evaluations.zeta_powers[0]
        )
        full_logup_sum = (
            self.separate_relation.evaluate(polynomial_evaluations)[0]
            * polynomial_evaluations.zeta_powers[0]
        )
        return (
            full_sum == self.target_sum
            and full_logup_sum == self.logup_correctness_target_sum
            and polynomial_evaluations.zeta_powers[0]
            == evaluate_multilinear_zeta_power_polynomial(
                self.round_challenges, self.sumcheck_challenges.zeta
            ),
            self.round_challenges,
            polynomial_evaluations,
        )


class SumcheckProverTest(unittest.TestCase):
    def test_one_round(self):
        from circuit import CircuitBuilder
        from uint import Uint8
        from transcript import ProverTranscript

        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr(1))
        cb = CircuitBuilder()
        a = Uint8(cb, 0xFF)
        b = Uint8(cb, 0xF)
        d = a ^ b
        d = a ^ b
        d = a ^ b
        d = a ^ b
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        # c_ct = a_ct * b_ct
        instance = Instance(cb)
        instance.generate_zeta_power_polynomial(Fr(2))
        sumcheck_challenges = SumcheckChallenges(zeta=Fr(2))
        relation_challenges = RelationChallenges(Fr(10), Fr(11))
        instance.generate_permutation_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        instance.generate_logup_inverse_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        sumcheck_prover = SumcheckProver(
            instance, prover_transcript, sumcheck_challenges, relation_challenges
        )

        sumcheck_prover.alpha = Fr(-1)
        sumcheck_prover.prove_round()
        round_proof = prover_transcript.export_proof()
        verifier_transcript = VerifierTranscript(round_proof)
        verifier_transcript.get_Fr_from_prover()
        sumcheck_verifier = SumcheckVerifier(
            instance.instance_size,
            verifier_transcript,
            sumcheck_challenges,
            relation_challenges,
        )
        sumcheck_verifier.alpha = Fr(-1)
        result = sumcheck_verifier.verify_round()
        self.assertTrue(result)

    def test_full(self):
        from circuit import CircuitBuilder
        from uint import Uint8
        from transcript import ProverTranscript

        prover_transcript = ProverTranscript()
        prover_transcript.send_to_verifier(Fr(1))
        cb = CircuitBuilder()
        a = Uint8(cb, 0xFF)
        b = Uint8(cb, 0xF)
        d = a ^ b
        d = a ^ b
        d = a ^ b
        d = a ^ b
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        # c_ct = a_ct * b_ct
        instance = Instance(cb)
        instance.generate_zeta_power_polynomial(Fr(2))
        sumcheck_challenges = SumcheckChallenges(zeta=Fr(2))
        relation_challenges = RelationChallenges(Fr(10), Fr(11))
        instance.generate_permutation_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        instance.generate_logup_inverse_polynomial(
            relation_challenges.beta, relation_challenges.gamma
        )
        sumcheck_prover = SumcheckProver(
            instance, prover_transcript, sumcheck_challenges, relation_challenges
        )
        sumcheck_prover.prove()
        round_proof = prover_transcript.export_proof()
        verifier_transcript = VerifierTranscript(round_proof)
        verifier_transcript.get_Fr_from_prover()
        sumcheck_verifier = SumcheckVerifier(
            instance.instance_size,
            verifier_transcript,
            sumcheck_challenges,
            relation_challenges,
        )
        (success, round_challenges, resulting_evaluation) = sumcheck_verifier.verify()
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()
