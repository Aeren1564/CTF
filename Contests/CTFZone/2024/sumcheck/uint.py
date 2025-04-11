from circuit import CircuitBuilder, CircuitRow, WitnessIndexRow
from ff import Fr
from hashlib import sha1
import struct
import unittest


XOR_TABLE_INDEX = struct.unpack("<Q", sha1(b"xor").digest()[:8])[0]
xor_lookup_table = []
for i in range(1 << 4):
    for j in range(1 << 4):
        xor_lookup_table.append((i, j, i ^ j))
RANGE_CONTRAIN_4_BIT_TUPLE_INDEX = struct.unpack(
    "<Q", sha1(b"range_constrain_2_4_bit_indices").digest()[:8]
)[0]
range_constraint_4_bit_table = []
for i in range(1 << 4):
    for j in range(1 << 4):
        range_constraint_4_bit_table.append((i, j, 0))


class Uint8:
    def __init__(self, builder: CircuitBuilder, value, empty=False):
        self.builder = builder
        if not empty:
            self.witness_index = self.builder.add_variable(value)
        if type(value) == Fr:
            self.value = value.value
        else:
            self.value = value
        assert self.value < (1 << 8)
        assert self.value >= 0

    @staticmethod
    def from_witness_index(builder, witness_index):
        temp = Uint8(builder, 0, True)
        temp.value = builder.get_variable_value(witness_index)
        temp.builder = builder
        temp.witness_index = witness_index
        return temp

    def fix_witness(self):
        self.builder.create_constant_gate(self.witness_index, self.value)

    def __xor__(self, other):
        self.builder.initialize_table(XOR_TABLE_INDEX, xor_lookup_table)
        lo_part = self.value & 15
        hi_part = self.value >> 4
        other_lo_part = other.value & 15
        other_hi_part = other.value >> 4
        hi_part_witness_index = self.builder.add_variable(hi_part)
        other_hi_part_witness_index = self.builder.add_variable(other_hi_part)
        new_element = self.value ^ other.value
        new_element_lo_part = new_element & 15
        new_element_hi_part = new_element >> 4
        new_element_witness_index = self.builder.add_variable(new_element)
        new_element_hi_witness_index = self.builder.add_variable(new_element_hi_part)

        self.builder.create_lookup_gate(
            self.witness_index,
            other.witness_index,
            new_element_witness_index,
            XOR_TABLE_INDEX,
            Fr(-16),
            Fr(-16),
            Fr(-16),
        )
        self.builder.create_lookup_gate(
            hi_part_witness_index,
            other_hi_part_witness_index,
            new_element_hi_witness_index,
            XOR_TABLE_INDEX,
            Fr(0),
            Fr(0),
            Fr(0),
        )

        return Uint8.from_witness_index(self.builder, new_element_witness_index)


class TestUint(unittest.TestCase):
    def test_xor(self):
        cb = CircuitBuilder()
        a = Uint8(cb, 0xFF)
        b = Uint8(cb, 0xF)
        c = Uint8(cb, 0xF0)
        d = a ^ b ^ c
        self.assertTrue(d.value == 0)
        cb.print_circuit()


if __name__ == "__main__":
    unittest.main()
