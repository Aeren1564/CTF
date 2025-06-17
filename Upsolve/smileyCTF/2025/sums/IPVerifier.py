"""
Interactive Verifier of Multilinear Polynomial Sum
Tom Shen
"""
import math
from random import Random
from typing import List, Tuple

from polynomial import MVLinear

DEFAULT_MAX_ALLOWED_SOUNDNESS_ERROR = 2 ** (-32)


class InteractiveVerifier:
    """
    An interactive verifier that verifies the sum of the multi-linear polynomial
    """

    def __init__(self, seed: int, polynomial: MVLinear, asserted_sum: int,
                 maxAllowedSoundnessError: float = DEFAULT_MAX_ALLOWED_SOUNDNESS_ERROR):
        """
        Initialize the protocol of the verifier.
        :param seed: the random source
        :param polynomial: The multilinear function
        :param asserted_sum: The proposed sum (0 and 1) of the multilinear function (which is to be verified)
        :param maxAllowedSoundnessError: the maximum soundness error allowed
        """
        self.p: int = polynomial.p
        """
        The field size
        """
        self.poly: MVLinear = polynomial
        self.asserted_sum: int = asserted_sum % self.p
        self.rand: Random = Random()
        self.rand.seed(seed)

        self.active: bool = True
        self.convinced: bool = False

        # check soundness
        if self.soundnessError() > maxAllowedSoundnessError:
            raise SoundnessErrorException(f"Soundness error {self.soundnessError()} exceeds maximum "
                                          f"allowed soundness error {maxAllowedSoundnessError}\n"
                                          f"Try to have a prime "
                                          f"with size "
                                          f">= {self.requiredFieldLengthBit(maxAllowedSoundnessError)} bits")

        # some edge case: if univariate or constant: no need to be interactive
        if polynomial.num_variables == 0:
            if (asserted_sum - polynomial.eval([])) % self.p == 0:
                self._convince_and_close()
                return
            else:
                self._reject_and_close()
                return
        if polynomial.num_variables == 1:
            result = (polynomial.eval([0]) + polynomial.eval([1])) % self.p
            if (asserted_sum - result) % self.p == 0:
                self._convince_and_close()
                return
            else:
                self._reject_and_close()
                return

        self.points: List[int] = [0] * self.poly.num_variables
        """
        the fixed points that are already decided by the verifier. At round i, [0, i-1] are decided
        """

        self.round: int = 0
        """
        which variable the verifier is summing (at round i, var 0 to var (i-1) is fixed, and the verifier is listening 
        to the univariate function of variable i where var[i+1, n] is summed over.  
        """

        self.expect: int = self.asserted_sum
        """
        The expected sum value at round i
        """

    def soundnessError(self) -> float:
        """
        Get the soundness error according to the MVLinear and field size.
        :return: The float representing the upper bound of probability of accepting when assertion is invalid.
        """

        n = self.poly.num_variables
        return (n * n) / self.p

    def requiredFieldLengthBit(self, e: float) -> int:
        """
        :param e: the maximum allowed soundness error
        :return: The minimum size of prime required to meet the soundness error constraint.
        """
        n = self.poly.num_variables
        minP = (n * n) / e
        return math.ceil(math.log(minP, 2)) + 1

    def randomR(self) -> int:
        return self.rand.randint(0, self.p)

    def talk(self, p0: int, p1: int) -> Tuple[bool, int]:
        """
        Send the verifier the univariate linear polynomial P(x).
        At round i, P(x) = sum over b: P(r_1, ..., r_i-1, x, b_i+1, b_i+2, ...)
        where r is fixed (as proposed by self.points)
        :param p0: P(0)
        :param p1: P(1)
        :return: a tuple (accept?, random r for x). If accept? is false, the returned integer is meaningless.
        """

        # if the protocol is not active, throw an error
        if not self.active:
            raise RuntimeError("Unable to prove: the protocol is not active. ")

        # check that P(0) + P(1) is in fact self.expect
        p0 %= self.p
        p1 %= self.p
        if (p0 + p1) % self.p != self.expect % self.p:
            self._reject_and_close()
            return False, 0

        # pick r at random
        r: int = self.randomR()
        pr: int = (p0 + r * (p1 - p0)) % self.p  # gradient formula
        self.expect = pr
        self.points[self.round] = r

        # if not final step, end here
        if not (self.round + 1 == self.poly.num_variables):
            self.round += 1
            return True, r

        # final step: check all
        final_sum = self.poly.eval(self.points)
        if pr != final_sum:
            self._reject_and_close()
            return False, 0
        self._convince_and_close()
        return True, 0

    def _convince_and_close(self):
        """
        Accept the sum. Close the protocol.
        """
        self.convinced = True
        self.active = False

    def _reject_and_close(self):
        """
        Reject the sum. Close the protocol
        """
        self.convinced = False
        self.active = False


class SoundnessErrorException(Exception):
    pass