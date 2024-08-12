from ff import Fr
from circuit import CircuitBuilder, CircuitRow, WitnessIndexRow
import unittest


class Fr_ct:
    multiplicative_constant = Fr(0)
    witness_index = -1
    additive_constant = Fr(0)
    builder = None

    def __init__(self, a_c=Fr(0), m_c=Fr(0), witness_index=-1, builder=None):
        self.builder = builder
        self.multiplicative_constant = Fr(m_c)
        self.additive_constant = Fr(a_c)
        self.witness_index = witness_index

    @staticmethod
    def create_witness(builder, field_value):
        temp = Fr_ct()
        temp.builder = builder
        temp.multiplicative_constant = Fr(1)
        temp.additive_constant = Fr(0)
        temp.witness_index = builder.add_variable(field_value)
        return temp

    def normalize(self):
        assert self.multiplicative_constant != Fr(0)

        new_value = (
            self.multiplicative_constant
            * self.builder.get_variable_value(self.witness_index)
            + self.additive_constant
        )

        new_index = self.builder.add_variable(new_value)

        self.builder.create_poly_gate(
            CircuitRow(
                Fr(0),
                Fr(1),
                Fr(0),
                self.multiplicative_constant,
                Fr(0),
                Fr(-1),
                self.additive_constant,
            ),
            WitnessIndexRow(self.witness_index, self.builder.zero_index, new_index),
        )

        return Fr_ct(Fr(0), Fr(1), new_index, self.builder)

    def __add__(self, other):
        if self.multiplicative_constant == Fr(0):
            if other.multiplicative_constant == Fr(0):
                return Fr_ct(self.additive_constant + other.additive_constant)
            else:
                return Fr_ct(
                    other.additive_constant + self.additive_constant,
                    other.multiplicative_constant,
                    other.witness_index,
                    other.builder,
                )
        else:
            if other.multiplicative_constant == Fr(0):
                return Fr_ct(
                    other.additive_constant + self.additive_constant,
                    self.multiplicative_constant,
                    self.witness_index,
                    self.builder,
                )
            elif other.witness_index == self.witness_index:
                return Fr_ct(
                    self.additive_constant + other.additive_constant,
                    self.multiplicative_constant + other.multiplicative_constant,
                    self.witness_index,
                    self.builder,
                )
            else:
                new_value = (
                    self.multiplicative_constant
                    * self.builder.get_variable_value(self.witness_index)
                    + self.additive_constant
                    + other.multiplicative_constant
                    * self.builder.get_variable_value(other.witness_index)
                    + other.additive_constant
                )
                new_index = self.builder.add_variable(new_value)

                self.builder.create_poly_gate(
                    CircuitRow(
                        Fr(0),
                        Fr(1),
                        Fr(0),
                        self.multiplicative_constant,
                        other.multiplicative_constant,
                        Fr(-1),
                        self.additive_constant + other.additive_constant,
                    ),
                    WitnessIndexRow(self.witness_index, other.witness_index, new_index),
                )
                return Fr_ct(Fr(0), Fr(1), new_index, self.builder)


class TestFF_CT_Methods(unittest.TestCase):
    def test_add_constants(self):
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct(a)
        b_ct = Fr_ct(b)
        for i in range(20):
            (a, b) = (b, a + b)
            (a_ct, b_ct) = (b_ct, a_ct + b_ct)
        self.assertTrue(a_ct.additive_constant == a)
        self.assertTrue(b_ct.additive_constant == b)

    def test_add_variables(self):
        cb = CircuitBuilder()
        a = Fr(1)
        b = Fr(1)
        a_ct = Fr_ct.create_witness(cb, a)
        b_ct = Fr_ct.create_witness(cb, b)
        for i in range(20):
            (a, b) = (b, a + b)
            (a_ct, b_ct) = (b_ct, a_ct + b_ct)

        a_ct = a_ct.normalize()
        b_ct = b_ct.normalize()

        self.assertTrue(cb.get_variable_value(a_ct.witness_index) == a)
        self.assertTrue(cb.get_variable_value(b_ct.witness_index) == b)
        cb.print_circuit()


if __name__ == "__main__":
    unittest.main()
