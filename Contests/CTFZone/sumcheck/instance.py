from polynomial import batch_inverse
from circuit import CircuitBuilder
from ff import Fr, alt_bn128_r
from collections import namedtuple
from uint import Uint8
from relations import PermutationConsequentRelationNoPublicInputs, RelationChallenges
import random
import unittest
from proof_polynomials import *


def compute_permutation_mapping(circuit_builder: CircuitBuilder):
    num_gates = circuit_builder.get_num_gates()
    cycles = dict()

    def add_to_cycle(gate_index, polynomial_index, real_variable_index):
        if real_variable_index in cycles.keys():
            cycles[real_variable_index].extend([(gate_index, polynomial_index)])
        else:
            cycles[real_variable_index] = [(gate_index, polynomial_index)]

    for i in range(num_gates):
        witness_indices = circuit_builder.witness_indices[i]
        real_index_w_l = circuit_builder.real_variable_indices[witness_indices.w_l]
        real_index_w_r = circuit_builder.real_variable_indices[witness_indices.w_r]
        real_index_w_o = circuit_builder.real_variable_indices[witness_indices.w_o]
        add_to_cycle(i, 0, real_index_w_l)
        add_to_cycle(i, 1, real_index_w_r)
        add_to_cycle(i, 2, real_index_w_o)

    permutation_map = dict()
    for key in cycles.keys():
        cycle_permutation = cycles[key]
        for i in range(len(cycle_permutation)):
            permutation_map[cycle_permutation[i]] = cycle_permutation[
                (i + 1) % len(cycle_permutation)
            ]
    return permutation_map


class Instance:

    def __init__(self, circuit_builder, disable_lookup_multiplicity=False):
        self.builder = circuit_builder
        num_gates = circuit_builder.get_num_gates()
        num_table_rows = circuit_builder.get_num_table_rows()
        self.instance_size = max(num_gates, num_table_rows)
        instance_size = self.instance_size
        self.all_polynomials = AllPolynomials(
            *[[] for _ in range(NUMBER_OF_POLYNOMIALS)]
        )

        permutation_map = compute_permutation_mapping(circuit_builder)
        # Fill lagrange polynomials
        self.all_polynomials.lagrange_first.extend(
            [Fr(0) for _ in range(self.instance_size)]
        )
        self.all_polynomials.lagrange_first[0] = Fr(1)
        self.all_polynomials.lagrange_last.extend(
            [Fr(0) for _ in range(self.instance_size)]
        )
        self.all_polynomials.lagrange_last[-1] = Fr(1)

        # Fill id and sigma polynomials
        for i in range(instance_size):
            self.all_polynomials.id_l.append(Fr(i + 1))
            self.all_polynomials.id_r.append(Fr(i + 1 + instance_size))
            self.all_polynomials.id_o.append(Fr(i + 1 + 2 * instance_size))
            next_left = (
                permutation_map[(i, 0)] if (i, 0) in permutation_map.keys() else (i, 0)
            )
            next_right = (
                permutation_map[(i, 1)] if (i, 1) in permutation_map.keys() else (i, 1)
            )
            next_output = (
                permutation_map[(i, 2)] if (i, 2) in permutation_map.keys() else (i, 2)
            )
            self.all_polynomials.sigma_l.append(
                Fr(1 + next_left[0] + next_left[1] * instance_size)
            )
            self.all_polynomials.sigma_r.append(
                Fr(1 + next_right[0] + next_right[1] * instance_size)
            )
            self.all_polynomials.sigma_o.append(
                Fr(1 + next_output[0] + next_output[1] * instance_size)
            )
        # Fill selectors
        for i in range(num_gates):
            selector_row = circuit_builder.rows[i]
            self.all_polynomials.q_lookup.append(selector_row.q_lookup)
            self.all_polynomials.q_arith.append(selector_row.q_arith)
            self.all_polynomials.q_m.append(selector_row.q_m)
            self.all_polynomials.q_l.append(selector_row.q_l)
            self.all_polynomials.q_r.append(selector_row.q_r)
            self.all_polynomials.q_o.append(selector_row.q_o)
            self.all_polynomials.q_c.append(selector_row.q_c)
        for i in range(self.instance_size - num_gates):
            self.all_polynomials.q_lookup.append(Fr(0))
            self.all_polynomials.q_arith.append(Fr(0))
            self.all_polynomials.q_m.append(Fr(0))
            self.all_polynomials.q_l.append(Fr(0))
            self.all_polynomials.q_r.append(Fr(0))
            self.all_polynomials.q_o.append(Fr(0))
            self.all_polynomials.q_c.append(Fr(0))
        # Fill tables
        table_indices = list(self.builder.lookup_tables.keys())
        table_indices.sort()
        for table_index in table_indices:
            lookup_table = self.builder.lookup_tables[table_index]

            def sort_func(entry):
                (a, b, c) = entry
                if type(a) == Fr:
                    a = a.value
                if type(b) == Fr:
                    b = b.value
                if type(c) == Fr:
                    c = c.value
                return ((a * alt_bn128_r) + b) * alt_bn128_r + c

            lookup_table.sort(key=sort_func)
            for a, b, c in lookup_table:
                self.all_polynomials.table_0.append(Fr(table_index))
                self.all_polynomials.table_1.append(Fr(a))
                self.all_polynomials.table_2.append(Fr(b))
                self.all_polynomials.table_3.append(Fr(c))
        self.lookup_dict = dict()
        for i in range(num_table_rows):
            self.lookup_dict[
                tuple(
                    map(
                        lambda x: x.value,
                        (
                            self.all_polynomials.table_0[i],
                            self.all_polynomials.table_1[i],
                            self.all_polynomials.table_2[i],
                            self.all_polynomials.table_3[i],
                        ),
                    )
                )
            ] = i
        for i in range(self.instance_size - num_table_rows):
            self.all_polynomials.table_0.append(Fr(0))
            self.all_polynomials.table_1.append(Fr(0))
            self.all_polynomials.table_2.append(Fr(0))
            self.all_polynomials.table_3.append(Fr(0))

        # Fill witnesses
        for i in range(num_gates):
            witness_indices = self.builder.witness_indices[i]
            self.all_polynomials.w_l.append(
                Fr(self.builder.get_variable_value(witness_indices.w_l))
            )
            self.all_polynomials.w_r.append(
                Fr(self.builder.get_variable_value(witness_indices.w_r))
            )
            self.all_polynomials.w_o.append(
                Fr(self.builder.get_variable_value(witness_indices.w_o))
            )

        for i in range(self.instance_size - num_gates):
            self.all_polynomials.w_l.append(Fr(0))
            self.all_polynomials.w_r.append(Fr(0))
            self.all_polynomials.w_o.append(Fr(0))
        self.all_polynomials.w_l_shift.extend(self.all_polynomials.w_l[1:] + [Fr(0)])
        self.all_polynomials.w_r_shift.extend(self.all_polynomials.w_r[1:] + [Fr(0)])
        self.all_polynomials.w_o_shift.extend(self.all_polynomials.w_o[1:] + [Fr(0)])
        self.all_polynomials.table_multiplicity.extend(
            [Fr(0) for _ in range(self.instance_size)]
        )
        if not disable_lookup_multiplicity:
            for i in range(num_gates):
                if self.all_polynomials.q_lookup[i] != Fr(0):
                    self.all_polynomials.table_multiplicity[
                        self.lookup_dict[
                            tuple(
                                map(
                                    lambda x: x.value,
                                    (
                                        self.all_polynomials.q_m[i],
                                        self.all_polynomials.w_l[i]
                                        + self.all_polynomials.q_l[i]
                                        * self.all_polynomials.w_l_shift[i],
                                        self.all_polynomials.w_r[i]
                                        + self.all_polynomials.q_r[i]
                                        * self.all_polynomials.w_r_shift[i],
                                        self.all_polynomials.w_o[i]
                                        + self.all_polynomials.q_o[i]
                                        * self.all_polynomials.w_o_shift[i],
                                    ),
                                )
                            )
                        ]
                    ] += Fr(1)

    def generate_zeta_power_polynomial(self, zeta):
        current_power = Fr(1)
        for _ in range(self.instance_size):
            self.all_polynomials.zeta_powers.append(current_power)
            current_power *= zeta

    def generate_permutation_polynomial(self, beta, gamma):
        numerators = [Fr(1)]
        denominators = [Fr(1)]
        permutation_relation = PermutationConsequentRelationNoPublicInputs(
            RelationChallenges(beta, gamma)
        )
        for i in range(self.instance_size):
            numerators.append(
                numerators[-1]
                * permutation_relation.compute_numerator(self.all_polynomials, i)
            )
            denominators.append(
                denominators[-1]
                * permutation_relation.compute_denominator(self.all_polynomials, i)
            )
        denominators = batch_inverse(denominators)

        permutation_pre_polynomial = [a * b for (a, b) in zip(numerators, denominators)]
        assert permutation_pre_polynomial[-1] == Fr(1)
        self.all_polynomials.permutation.extend(
            [Fr(0)] + [Fr(x) for x in permutation_pre_polynomial[1:-1]]
        )
        self.all_polynomials.permutation_shift.extend(
            [Fr(x) for x in permutation_pre_polynomial[1:-1]] + [Fr(0)]
        )

        ev = permutation_relation.evaluate(self.all_polynomials)

    def generate_logup_inverse_polynomial(self, beta, gamma):
        numerators = []
        beta_sqr = beta * beta
        beta_cube = beta_sqr * beta
        for i in range(self.instance_size):
            numerator = (
                gamma
                + self.all_polynomials.q_m[i]
                + (
                    self.all_polynomials.w_l[i]
                    + self.all_polynomials.q_l[i] * self.all_polynomials.w_l_shift[i]
                )
                * beta
                + (
                    self.all_polynomials.w_r[i]
                    + self.all_polynomials.q_r[i] * self.all_polynomials.w_r_shift[i]
                )
                * beta_sqr
                + (
                    self.all_polynomials.w_o[i]
                    + self.all_polynomials.q_o[i] * self.all_polynomials.w_o_shift[i]
                )
                * beta_cube
            ) * (
                gamma
                + self.all_polynomials.table_0[i]
                + self.all_polynomials.table_1[i] * beta
                + self.all_polynomials.table_2[i] * beta_sqr
                + self.all_polynomials.table_3[i] * beta_cube
            )
            numerators.append(numerator)
        denominators = batch_inverse(numerators)
        self.all_polynomials.log_inverse.extend(denominators)


class TestInstance(unittest.TestCase):

    def test_batch_inverse(self):
        polynomial = [Fr(i + 1) for i in range(10)]
        inverse_polynomial = batch_inverse(polynomial)
        self.assertEqual(len(polynomial), len(inverse_polynomial))
        for a, b in zip(polynomial, inverse_polynomial):
            self.assertEqual(a * b, Fr(1))

    def test_polynomial_creation(self):
        cb = CircuitBuilder()
        a = Uint8(cb, 0xFF)
        b = Uint8(cb, 0xF)
        d = a ^ b
        e = a ^ b
        instance = Instance(cb)

        def to_printable_list(polynomial):
            return list(
                map(
                    lambda x: x.value if type(x) == Fr else x,
                    polynomial[:16],
                )
            )

        print("id_l[:16]:")
        print(to_printable_list(instance.all_polynomials.id_l))
        print("id_r[:16]:")
        print(to_printable_list(instance.all_polynomials.id_r))
        print("id_o[:16]:")
        print(to_printable_list(instance.all_polynomials.id_o))
        beta = Fr.from_bytes(random.randbytes(32))
        gamma = Fr.from_bytes(random.randbytes(32))
        left = Fr(1)
        right = Fr(1)
        for i in range(16):
            left *= (
                instance.all_polynomials.w_l[i]
                + instance.all_polynomials.id_l[i] * beta
                + gamma
            )
            left *= (
                instance.all_polynomials.w_r[i]
                + instance.all_polynomials.id_r[i] * beta
                + gamma
            )
            left *= (
                instance.all_polynomials.w_o[i]
                + instance.all_polynomials.id_o[i] * beta
                + gamma
            )

            right *= (
                instance.all_polynomials.w_l[i]
                + instance.all_polynomials.sigma_l[i] * beta
                + gamma
            )
            right *= (
                instance.all_polynomials.w_r[i]
                + instance.all_polynomials.sigma_r[i] * beta
                + gamma
            )
            right *= (
                instance.all_polynomials.w_o[i]
                + instance.all_polynomials.sigma_o[i] * beta
                + gamma
            )
        self.assertEqual(left, right, "Permutation check fails")

        print("sigma_l[:16]:")
        print(to_printable_list(instance.all_polynomials.sigma_l))
        print("sigma_r[:16]:")
        print(to_printable_list(instance.all_polynomials.sigma_r))
        print("sigma_o[:16]:")
        print(to_printable_list(instance.all_polynomials.sigma_o))
        print("Table_3[:16]:")
        print(to_printable_list(instance.all_polynomials.table_3))


if __name__ == "__main__":
    unittest.main()
