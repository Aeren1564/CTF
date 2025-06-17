from typing import List, Tuple

from polynomial import MVLinear
from IPVerifier import InteractiveVerifier
import time


def binaryToList(b: int, numVariables: int) -> List[int]:
    """
    Change binary form to list of arguments.
    :param b: The binary form. For example: 0b1011 means g(x0=1, x1 = 0, x2 = 1, x3 = 1)
    :param numVariables: The number of variables
    :return: List of integer where the ith element is xi.
    """
    lst: List[int] = [0] * numVariables
    i = 0
    while b != 0:
        lst[i] = b & 1
        b >>= 1
        i += 1
    return lst


class InteractiveLinearProver:
    """
    A linear honest prover of sum-check protocol for multilinear polynomial using dynamic programming.
    """

    def __init__(self, polynomial: MVLinear):
        self.poly: MVLinear = polynomial
        self.p = self.poly.p  # field size

    def attemptProve(self, A: List[int], verifier: InteractiveVerifier, showDialog: bool = False) -> float:
        """
        Attempt to prove the sum.
        :param A: The bookkeeping table
        :param verifier:
        :param showDialog: whether show the dialog for test purpose
        :return: the running time of verifier
        """
        l = self.poly.num_variables
        vT: float = 0
        for i in range(1, l + 1):  # round
            p0 = 0  # sum over P(fixed, 0, ...)
            p1 = 0  # sum over P(fixed, 1, ...)
            for b in range(2**(l-i)):
                p0 = (p0 + A[b << 1]) % self.p
                p1 = (p1 + A[(b << 1) + 1]) % self.p
            if showDialog:
                print(f"Round {i}: Prover Send P{i}(0) = {p0}, P{i}(1) = {p1}. "
                      f"P{i}(0) + P{i}(1) = {(p0 + p1) % self.p}")
            start = time.time() * 1000  # timing
            result, r = verifier.talk(p0, p1)
            end = time.time() * 1000    # timing
            assert result
            vT += end - start   # timing
            if showDialog and verifier.active:
                print(f"Verifier expects P{i+1}(0) + P{i+1}(1) to be P{i}({r}) = {verifier.expect}")
            for b in range(2**(l-i)):
                A[b] = (A[b << 1] * (1 - r) + A[(b << 1) + 1] * r) % self.p

        return vT

    def calculateTable(self) -> Tuple[List[int], int]:
        """
        :return: A bookkeeping table where the index is the binary form of argument of polynomial and value is the
        evaluated value; the sum
        """

        A: List[int] = [0] * (2 ** self.poly.num_variables)
        s = 0
        for p in range(2 ** self.poly.num_variables):
            A[p] = self.poly.eval(binaryToList(p, self.poly.num_variables))
            s = (s + A[p]) % self.p

        return A, s
