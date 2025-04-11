import unittest
from py_ecc.optimized_bn128.optimized_curve import (
    G1,
    G2,
    Z1,
    multiply,
    normalize,
    add,
    curve_order,
)
from py_ecc.optimized_bn128.optimized_pairing import pairing
from py_ecc.fields import optimized_bn128_FQ, optimized_bn128_FQ2
from srs_gen import load_from_file
from ff import Fr, Fq
from copy import deepcopy

import logging
import os
from multiprocessing import Pool


def convert_to_working_point(commitment):
    coordinates = []
    for element in commitment:
        if type(element) == int:
            coordinates.append(optimized_bn128_FQ(element))
        elif type(element) == Fq:
            coordinates.append(optimized_bn128_FQ(int(element.value)))
        elif type(element) == optimized_bn128_FQ:
            coordinates.append(element)
        else:
            raise Exception(f"Type: {type(element)}")
    if len(coordinates) == 2:
        coordinates.append(optimized_bn128_FQ(1))
        if coordinates[0] == optimized_bn128_FQ(0) and coordinates[
            1
        ] == optimized_bn128_FQ(0):
            return Z1
    return tuple(coordinates)


def batch_commitments(commitments, batching_scalar, starting_scalar=Fr(1)):
    working_commitments = list(map(convert_to_working_point, commitments))
    result = Z1
    running_scalar = starting_scalar
    for commitment in working_commitments:
        result = add(result, multiply(commitment, running_scalar.value))
        running_scalar *= batching_scalar
    return result


def map_to_optimized_fq(elements):
    return tuple(
        map(
            optimized_bn128_FQ,
            [x if (type(x) == int) else x.n for x in elements],
        )
    )


def msm(scalars_and_points):
    if len(scalars_and_points) == 0:
        return Z1
    first_pair = scalars_and_points[0]
    start = multiply(
        first_pair[1],
        # G1,
        first_pair[0].value,
    )
    for i in range(1, len(scalars_and_points)):
        current_pair = scalars_and_points[i]
        adder = multiply(
            current_pair[1],
            # G1,
            current_pair[0].value,
        )

        start = add(start, adder)
    return start


class KZG:
    def __init__(self, srs_file="./ronk_srs.bin"):
        self.srs = load_from_file(srs_file)
        self.srs_size = len(self.srs[0])
        logging.log(logging.INFO, f"Loaded srs of size {self.srs_size}")

    def commit(self, polynomial):
        work_chunks = []  # List of (scalar, srs_element) tuples
        for i, scalar in enumerate(polynomial):
            work_chunks.append((scalar, self.srs[0][i]))

        cpu_count = os.cpu_count()
        chunk_size = len(polynomial) // cpu_count
        if chunk_size * cpu_count < len(polynomial):
            chunk_size += 1
        if len(polynomial) > cpu_count:
            prepared_workloads = [
                work_chunks[i : i + chunk_size]
                for i in range(0, len(polynomial), chunk_size)
            ]

            with Pool(cpu_count) as p:
                results = p.map(msm, prepared_workloads)
            start = results[0]
            for i in range(1, len(results)):
                start = add(start, results[i])
        else:
            start = msm(work_chunks)
        return normalize(start)

    def open(self, polynomial, x):
        running_power = Fr(1)
        result = Fr(0)
        for element in polynomial:
            result += element * running_power
            running_power *= x
        current_remainder = polynomial[0] - result
        quotient_polynomial = []
        q_s = Fr(0)
        for i in range(1, len(polynomial)):
            multiplicand = -current_remainder / x
            q_s += multiplicand
            quotient_polynomial.append(multiplicand)
            current_remainder = polynomial[i] - multiplicand
        assert current_remainder == Fr(0)
        return (x, result, self.commit(quotient_polynomial))

    def verify(self, commitment, opening):
        if len(commitment) == 2:
            commitment = (commitment[0], commitment[1], optimized_bn128_FQ(1))
        (x, result, quotient_commitment) = opening
        if len(quotient_commitment) == 2:
            quotient_commitment = (
                quotient_commitment[0],
                quotient_commitment[1],
                optimized_bn128_FQ(1),
            )
        left_side_g1 = add(commitment, multiply(G1, curve_order - result.value))
        left_side_g2 = G2
        right_side_g1 = quotient_commitment
        right_side_g2 = add(self.srs[1], multiply(G2, curve_order - x.value))
        return pairing(left_side_g2, left_side_g1) == pairing(
            right_side_g2, right_side_g1
        )


class TestKZGMethods(unittest.TestCase):
    def test_sub(self):
        a = Fr(0)
        b = Fr(1)
        t = b
        coeffs = []
        for i in range(200):
            coeffs.append(t)
            a += t
            t = t + t
        kzg = KZG()
        commitment = kzg.commit(coeffs)
        proof = kzg.open(coeffs, Fr(1))
        self.assertTrue(kzg.verify(commitment, proof))


if __name__ == "__main__":
    unittest.main()
