from ff import Fr
from proof_polynomials import AllPolynomials
from collections import namedtuple

RelationChallenges = namedtuple(
    "AllPolynomials", ["beta", "gamma"], defaults=[Fr(-2), Fr(-1)]
)


class ArithmeticRelation:
    def __init__(self, challenges):
        pass

    def get_power(self):
        return 4

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.q_arith)):
            result.append(
                all_polynomials.q_arith[i]
                * (
                    all_polynomials.q_m[i]
                    * all_polynomials.w_l[i]
                    * all_polynomials.w_r[i]
                    + all_polynomials.q_l[i] * all_polynomials.w_l[i]
                    + all_polynomials.q_r[i] * all_polynomials.w_r[i]
                    + all_polynomials.q_o[i] * all_polynomials.w_o[i]
                    + all_polynomials.q_c[i]
                )
            )
        return result


class PermutationConsequentRelationNoPublicInputs:

    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        pass

    def get_power(self):
        return 5

    def compute_numerator(self, all_polynomials: AllPolynomials, i: int):
        (beta, gamma) = self.challenges.beta, self.challenges.gamma
        return (
            (all_polynomials.id_l[i] + all_polynomials.w_l[i] * beta + gamma)
            * (all_polynomials.id_r[i] + all_polynomials.w_r[i] * beta + gamma)
            * (all_polynomials.id_o[i] + all_polynomials.w_o[i] * beta + gamma)
        )

    def compute_denominator(self, all_polynomials: AllPolynomials, i: int):
        (beta, gamma) = self.challenges.beta, self.challenges.gamma
        return (
            (all_polynomials.sigma_l[i] + all_polynomials.w_l[i] * beta + gamma)
            * (all_polynomials.sigma_r[i] + all_polynomials.w_r[i] * beta + gamma)
            * (all_polynomials.sigma_o[i] + all_polynomials.w_o[i] * beta + gamma)
        )

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.permutation)):
            result.append(
                (
                    (all_polynomials.lagrange_first[i] + all_polynomials.permutation[i])
                    * self.compute_numerator(all_polynomials, i)
                )
                - (
                    (
                        all_polynomials.permutation_shift[i]
                        + all_polynomials.lagrange_last[i]
                    )
                    * self.compute_denominator(all_polynomials, i)
                )
            )
        return result


class PermutationRelationLastElement:

    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        pass

    def get_power(self):
        return 5

    def evaluate(self, all_polynomials: AllPolynomials):
        result = []
        for i in range(len(all_polynomials.permutation)):
            result.append(
                all_polynomials.lagrange_last[i] * all_polynomials.permutation_shift[i]
            )
        return result


class LookupMainRelation:
    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        self.beta = challenges.beta
        self.gamma = challenges.gamma
        self.beta_sqr = challenges.beta * challenges.beta
        self.beta_cube = challenges.beta * self.beta_sqr
        pass

    def get_power(self):
        return 3

    def evaluate(self, all_polynomials: AllPolynomials):
        (gamma, beta, beta_sqr, beta_cube) = (
            self.gamma,
            self.beta,
            self.beta_sqr,
            self.beta_cube,
        )
        result = []
        for i in range(len(all_polynomials.log_inverse)):
            result.append(
                (
                    (
                        gamma
                        + all_polynomials.q_m[i]
                        + (
                            all_polynomials.w_l[i]
                            + all_polynomials.q_l[i] * all_polynomials.w_l_shift[i]
                        )
                        * beta
                        + (
                            all_polynomials.w_r[i]
                            + all_polynomials.q_r[i] * all_polynomials.w_r_shift[i]
                        )
                        * beta_sqr
                        + (
                            all_polynomials.w_o[i]
                            + all_polynomials.q_o[i] * all_polynomials.w_o_shift[i]
                        )
                        * beta_cube
                    )
                    * all_polynomials.log_inverse[i]
                    * all_polynomials.table_multiplicity[i]
                )
                - (
                    (
                        gamma
                        + all_polynomials.table_0[i]
                        + all_polynomials.table_1[i] * beta
                        + all_polynomials.table_2[i] * beta_sqr
                        + all_polynomials.table_3[i] * beta_cube
                    )
                    * all_polynomials.log_inverse[i]
                    * all_polynomials.q_lookup[i]
                )
            )
        return result


class LookupInverseCorrectness:
    def __init__(self, challenges: RelationChallenges):
        self.challenges = challenges
        self.beta = challenges.beta
        self.gamma = challenges.gamma
        self.beta_sqr = challenges.beta * challenges.beta
        self.beta_cube = challenges.beta * self.beta_sqr
        pass

    def get_power(self):
        return 3

    def evaluate(self, all_polynomials: AllPolynomials):
        (gamma, beta, beta_sqr, beta_cube) = (
            self.gamma,
            self.beta,
            self.beta_sqr,
            self.beta_cube,
        )
        result = []
        for i in range(len(all_polynomials.log_inverse)):
            result.append(
                (
                    (
                        gamma
                        + all_polynomials.q_m[i]
                        + (
                            all_polynomials.w_l[i]
                            + all_polynomials.q_l[i] * all_polynomials.w_l_shift[i]
                        )
                        * beta
                        + (
                            all_polynomials.w_r[i]
                            + all_polynomials.q_r[i] * all_polynomials.w_r_shift[i]
                        )
                        * beta_sqr
                        + (
                            all_polynomials.w_o[i]
                            + all_polynomials.q_o[i] * all_polynomials.w_o_shift[i]
                        )
                        * beta_cube
                    )
                    * all_polynomials.log_inverse[i]
                    * (
                        gamma
                        + all_polynomials.table_0[i]
                        + all_polynomials.table_1[i] * beta
                        + all_polynomials.table_2[i] * beta_sqr
                        + all_polynomials.table_3[i] * beta_cube
                    )
                    - Fr(1)
                )
            )
        return result
