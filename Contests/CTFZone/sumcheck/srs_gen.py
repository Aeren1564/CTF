from py_ecc.optimized_bn128.optimized_curve import (
    G1,
    G2,
    multiply,
    normalize,
    curve_order,
)
from py_ecc.optimized_bn128.optimized_pairing import pairing
from py_ecc.fields import optimized_bn128_FQ, optimized_bn128_FQ2
from Crypto.Util.number import long_to_bytes, bytes_to_long
import sys
from multiprocessing import Pool

from secrets import token_bytes

import sys
import os


class SRSError(Exception):
    def __init__(self, message):
        super().__init__(message)


FILE_MAGIC = b"BN254_RONK_SRS"
FIELD_BYTE_SIZE = 32


def generate_part_of_srs(inputs):
    (tau, chunk_size, srs_size, starting_index) = inputs
    srs_part = []
    current_power = pow(tau, starting_index, curve_order)
    end = min(starting_index + chunk_size, srs_size)
    for _ in range(starting_index, end):
        new_element = multiply(G1, current_power)
        srs_part.append(new_element)
        current_power = current_power * tau % curve_order
    prods = [optimized_bn128_FQ(1)]
    for i, el in enumerate(srs_part):
        prods.append(prods[i] * el[2])
    running_inverse = optimized_bn128_FQ(1) / prods[-1]
    for i in range(len(srs_part) - 1, -1, -1):
        prods[i] = prods[i] * running_inverse
        running_inverse = running_inverse * srs_part[i][2]
        srs_part[i] = (srs_part[i][0] * prods[i], srs_part[i][1] * prods[i])
    return srs_part


def generate_srs(srs_size):
    srs = []
    tau = bytes_to_long(token_bytes(64)) % curve_order
    print("Chosen tau: ", tau)
    cpu_count = os.cpu_count()
    assert srs_size > cpu_count
    chunk_size = srs_size // cpu_count
    if chunk_size * cpu_count < srs_size:
        chunk_size += 1

    with Pool(cpu_count) as p:
        results = p.map(
            generate_part_of_srs,
            list(
                [
                    (tau, chunk_size, srs_size, index)
                    for index in range(0, srs_size, chunk_size)
                ]
            ),
        )
    for result in results:
        srs.extend(result)
    g2_tau = multiply(G2, tau)
    print("Finished generation. Checking")
    assert pairing(g2_tau, (srs[-2][0], srs[-2][1], optimized_bn128_FQ(1))) == pairing(
        G2, (srs[-1][0], srs[-1][1], optimized_bn128_FQ(1))
    )
    g2_tau = normalize(g2_tau)
    return (srs, g2_tau)


def write_to_file(filename, srs_tuple):
    with open(filename, "wb") as f:
        f.write(FILE_MAGIC)
        (g1_srs, g2_tau) = srs_tuple

        (g2_x, g2_y) = g2_tau
        f.write(long_to_bytes(g2_x.coeffs[0], FIELD_BYTE_SIZE))
        f.write(long_to_bytes(g2_x.coeffs[1], FIELD_BYTE_SIZE))
        f.write(long_to_bytes(g2_y.coeffs[0], FIELD_BYTE_SIZE))
        f.write(long_to_bytes(g2_y.coeffs[1], FIELD_BYTE_SIZE))
        f.write(long_to_bytes(len(g1_srs), 4))
        for element in g1_srs:
            f.write(long_to_bytes(element[0].n, FIELD_BYTE_SIZE))
            f.write(long_to_bytes(element[1].n, FIELD_BYTE_SIZE))


def load_from_file(filename):
    with open(filename, "rb") as f:
        magic = f.read(len(FILE_MAGIC))
        if magic != FILE_MAGIC:
            raise SRSError("SRS file magic incorrect")

        def read_and_check_field():
            obj_bytes = f.read(FIELD_BYTE_SIZE)
            if len(obj_bytes) != FIELD_BYTE_SIZE:
                raise SRSError("Not enough bytes for the object being read")
            return bytes_to_long(obj_bytes)

        g2 = (
            optimized_bn128_FQ2([read_and_check_field(), read_and_check_field()]),
            optimized_bn128_FQ2([read_and_check_field(), read_and_check_field()]),
            optimized_bn128_FQ2([1, 0]),
        )
        srs_size_bytes = f.read(4)
        if len(srs_size_bytes) != 4:
            raise SRSError("Not enough bytes for the object being read")
        srs_size = bytes_to_long(srs_size_bytes)
        srs_g1s = []
        for i in range(srs_size):
            x = read_and_check_field()
            y = read_and_check_field()
            srs_g1s.append(
                (optimized_bn128_FQ(x), optimized_bn128_FQ(y), optimized_bn128_FQ(1))
            )
        assert pairing(g2, srs_g1s[-2]) == pairing(G2, srs_g1s[-1])
        return (srs_g1s, g2)


if __name__ == "__main__":
    if (len(sys.argv)) < 3:
        print(f"Usage: {sys.argv[0]} <srs_size> <output_file>")
        exit(0)
    srs = generate_srs(int(sys.argv[1]))
    write_to_file(sys.argv[2], srs)
