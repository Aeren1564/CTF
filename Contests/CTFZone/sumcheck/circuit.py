from ff import Fr
from collections import namedtuple

CircuitRow = namedtuple(
    "CircuitRow",
    ["q_lookup", "q_arith", "q_m", "q_l", "q_r", "q_o", "q_c"],
    defaults=([Fr(0) for _ in range(6)]),
)
WitnessIndexRow = namedtuple(
    "WitnessIndexRow", ["w_l", "w_r", "w_o"], defaults=[0, 0, 0]
)

LAST_VARIABLE_IN_CLASS = -1
FIRST_VARIABLE_IN_CLASS = -1


class CircuitBuilder:

    def add_variable(self, value: Fr):
        index = len(self.variables)
        self.variables.append(value)
        self.real_variable_indices.append(index)
        self.previous_variable_in_class.append(FIRST_VARIABLE_IN_CLASS)
        self.next_variable_in_class.append(LAST_VARIABLE_IN_CLASS)
        return index

    def get_variable_value(self, index):
        assert index < len(self.variables)
        return self.variables[self.real_variable_indices[index]]

    def connect(self, variable_index_1, variable_index_2, fail_on_inequality=True):
        if fail_on_inequality:
            assert self.variables[variable_index_1] == self.variables[variable_index_2]
        last_variable = variable_index_1
        while self.next_variable_in_class[last_variable] != LAST_VARIABLE_IN_CLASS:
            last_variable = self.next_variable_in_class[last_variable]
        first_variable = variable_index_2
        while (
            self.previous_variable_in_class[first_variable] != FIRST_VARIABLE_IN_CLASS
        ):
            first_variable = self.previous_variable_in_class[first_variable]
        new_real_variable_index = self.real_variable_indices[variable_index_1]
        next_var = first_variable
        self.real_variable_indices[next_var] = new_real_variable_index
        while self.previous_variable_in_class[next_var] != LAST_VARIABLE_IN_CLASS:
            self.real_variable_indices[next_var] = new_real_variable_index
            next_var = self.previous_variable_in_class[next_var]
        self.previous_variable_in_class[first_variable] = last_variable
        self.next_variable_in_class[last_variable] = first_variable

    def __init__(self) -> None:
        self.variables = []
        self.real_variable_indices = []
        self.previous_variable_in_class = []
        self.next_variable_in_class = []
        self.rows = []
        self.witness_indices = []
        self.lookup_tables = dict()
        self.zero_index = self.add_variable(Fr(0))
        self.one_index = self.add_variable(Fr(1))

        # # zero row for shifts
        self.rows.append(CircuitRow(Fr(0), Fr(0), Fr(0), Fr(0), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(self.zero_index, self.zero_index, self.zero_index)
        )
        # w_l[0] = 0
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(1), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(self.zero_index, self.zero_index, self.zero_index)
        )
        # w_l[1] = 1
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(0), Fr(1), Fr(0), Fr(0), Fr(-1)))
        self.witness_indices.append(
            WitnessIndexRow(self.one_index, self.zero_index, self.zero_index)
        )
        pass

    def create_poly_gate(self, selectors, indices):
        self.rows.append(selectors)
        self.witness_indices.append(indices)

    def create_binary_gate(self, variable_index):
        """x²-x = 0"""
        assert variable_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(1), Fr(-1), Fr(0), Fr(0), Fr(0)))
        self.witness_indices.append(
            WitnessIndexRow(variable_index, variable_index, self.zero_index)
        )

    def create_addition_gate(self, input1_index, input2_index, output_index, constant):
        """output=input1 + input2 + constant"""
        assert input1_index < len(self.variables)
        assert input2_index < len(self.variables)
        assert output_index < len(self.variables)
        self.rows.append(
            CircuitRow(Fr(0), Fr(1), Fr(0), Fr(1), Fr(1), Fr(-1), Fr(-constant))
        )
        self.witness_indices.append(
            WitnessIndexRow(input1_index, input2_index, output_index)
        )

    def create_constant_gate(self, input_index, constant):
        assert input_index < len(self.variables)
        self.rows.append(
            CircuitRow(Fr(0), Fr(1), Fr(0), Fr(1), Fr(0), Fr(0), -Fr(constant))
        )
        self.witness_indices.append(
            WitnessIndexRow(input_index, self.zero_index, self.zero_index)
        )

    def initialize_table(self, table_index, table):
        if table_index in self.lookup_tables.keys():
            return
        self.lookup_tables[table_index] = table

    def create_lookup_gate(
        self,
        element1_index,
        element2_index,
        element3_index,
        table_index,
        next_element1_multiplicand,
        next_element2_multiplicand,
        next_element3_multiplicand,
    ):
        assert table_index in self.lookup_tables.keys()
        # q_m - table index
        # q_l - left element multiplicand
        # q_r - right element multiplicand
        # q_o - output element multiplicand
        self.rows.append(
            CircuitRow(
                Fr(1),
                Fr(0),
                Fr(table_index),
                Fr(next_element1_multiplicand),
                Fr(next_element2_multiplicand),
                Fr(next_element3_multiplicand),
            )
        )
        self.witness_indices.append(
            WitnessIndexRow(element1_index, element2_index, element3_index)
        )

    def get_num_gates(self):
        return len(self.rows)

    def get_num_table_rows(self):
        total_rows = 0
        for key in self.lookup_tables.keys():
            total_rows += len(self.lookup_tables[key])
            return total_rows

    def create_multiplication_gate(self, input1_index, input2_index, output_index):
        """output=input1 + input2 + constant"""
        assert input1_index < len(self.variables)
        assert input2_index < len(self.variables)
        assert output_index < len(self.variables)
        self.rows.append(CircuitRow(Fr(0), Fr(1), Fr(1), Fr(0), Fr(0), Fr(-1), Fr(0)))
        self.witness_indices.append(WitnessIndexRow(input1_index, input2_index, output_index))

    def print_gate(self, index):
        assert index < len(self.rows)
        assert len(self.rows) == len(self.witness_indices)
        selector_row = self.rows[index]
        witness_row = self.witness_indices[index]
        if index == len(self.rows) - 1:
            witness_next_row = WitnessIndexRow(
                self.zero_index, self.zero_index, self.zero_index
            )
        else:
            witness_next_row = self.witness_indices[index + 1]
        if selector_row.q_arith.value != 0:
            print(
                ("%04d: " % index)
                + f" arithmetic: {selector_row.q_m.value} * v_{witness_row.w_l} * v_{witness_row.w_r} + {selector_row.q_l.value} * v_{witness_row.w_l} + {selector_row.q_r.value} * v_{witness_row.w_r} + {selector_row.q_o.value} * v_{witness_row.w_o} + {selector_row.q_c.value}"
            )
        elif selector_row.q_lookup.value != 0:
            print(
                "%04d: " % index
                + f"lookup: {selector_row.q_m.value} / (v_{witness_row.w_l} + {selector_row.q_l.value} * v_{witness_next_row.w_l} / (v_{witness_row.w_r} + {selector_row.q_r.value} * v_{witness_next_row.w_r} / (v_{witness_row.w_o} + {selector_row.q_o.value} * v_{witness_next_row.w_o})"
            )

    def print_circuit(self):
        for i in range(len(self.rows)):
            self.print_gate(i)


if __name__ == "__main__":
    cb = CircuitBuilder()
    # cb.print_gate(0)
    # cb.print_gate(1)
    cb.print_circuit()
    print()
    id1 = cb.add_variable(12)
    id2 = cb.add_variable(34)
    id3 = cb.add_variable(56)
    cb.initialize_table(0, [])
    cb.create_lookup_gate(id1, id2, id3, 0, 3, 2, 1)
    cb.print_circuit()
