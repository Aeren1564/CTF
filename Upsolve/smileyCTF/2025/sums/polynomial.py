import copy
import random
from typing import Dict, List, Union, Callable
#from IPython.display import display, Latex

from Crypto.Util.number import getPrime
class MVLinear:
    """
    A Sparse Representation of a multi-linear polynomial.
    """

    def __init__(self, num_variables: int, term: Dict[int, int], p: int):
        """
        :param num_variables: total number of variables
        :param term: the terms of the polynomial. Index is the binary representation of the vector, where
        the nth bit represents the nth variable. For example, 0b1011 represents term x0x1x3. The value represents the coefficient.
        :param p: the size of finite field
        """

        self.num_variables = num_variables
        self.terms: Dict[int, int] = dict()
        self.p = p
        for k,v in term.items():
            if k >> self.num_variables > 0:
                raise ValueError("Term is out of range.")
            if v % p == 0:
                continue
            if k in self.terms:
                self.terms[k] = (self.terms[k] + term[k]) % self.p
            else:
                self.terms[k] = term[k] % self.p

    def __repr__(self):
        limit = 8
        s = ""
        s += "MVLinear("
        for k in self.terms:
            s += " + "
            if limit == 0:
                s += "..."
                break
            s += str(self.terms[k])
            if k != 0:
                s += "*"

            i = 0
            while k != 0:
                if k & 1 == 1:
                    s += "x" + str(i)
                i += 1
                k >>= 1
            limit -= 1
        s += ")"
        return s

    def __copy__(self) -> 'MVLinear':
        t = self.terms.copy()
        return MVLinear(self.num_variables, t, self.p)

    __deepcopy__ = __copy__

    def _assert_same_type(self, other: 'MVLinear'):
        if not isinstance(other, MVLinear):
            raise TypeError("MVLinear can only be added with MVLinear")
        if other.p != self.p:
            raise TypeError("The function being added is not in the same field. ")

    def __add__(self, other: Union['MVLinear', int]) -> 'MVLinear':
        if type(other) is int:
            other = MVLinear(self.num_variables, {0b0: other}, self.p)
        self._assert_same_type(other)

        ans: MVLinear = copy.copy(self)
        ans.num_variables = max(self.num_variables, other.num_variables)

        for k in other.terms:
            if k in self.terms:
                ans.terms[k] = (ans.terms[k] + other.terms[k]) % self.p
                if ans.terms[k] == 0:
                    ans.terms.pop(k)
            else:
                ans.terms[k] = other.terms[k] % self.p

        return ans

    __radd__ = __add__

    def __sub__(self, other: Union['MVLinear', int]) -> 'MVLinear':
        if type(other) is int:
            other = MVLinear(self.num_variables, {0b0: other}, self.p)
        self._assert_same_type(other)

        ans: MVLinear = copy.copy(self)
        ans.num_variables = max(self.num_variables, other.num_variables)

        for k in other.terms:
            if k in self.terms:
                ans.terms[k] = (ans.terms[k] - other.terms[k]) % self.p
                if ans.terms[k] == 0:
                    ans.terms.pop(k)
            else:
                ans.terms[k] = (- other.terms[k]) % self.p

        return ans

    def __neg__(self):
        return 0 - self

    def __rsub__(self, other):
        if type(other) is int:
            other = MVLinear(self.num_variables, {0b0: other}, self.p)
        return other - self

    def __mul__(self, other: Union['MVLinear', int]) -> 'MVLinear':
        if type(other) is int:
            other = MVLinear(self.num_variables, {0b0: other}, self.p)
        self._assert_same_type(other)

        terms: Dict[int, int] = dict()
        # naive n^2 poly multiplication where n is number of terms
        for sk in self.terms:  # the term of self
            for ok in other.terms:  # the term of others
                if sk & ok > 0:
                    raise ArithmeticError("The product is no longer multi-linear function.")
                nk = sk + ok  # the result term
                if nk in terms:
                    terms[nk] = (terms[nk] + self.terms[sk] * other.terms[ok]) % self.p
                else:
                    terms[nk] = (self.terms[sk] * other.terms[ok]) % self.p
                if terms[nk] == 0:
                    terms.pop(nk)

        ans = MVLinear(max(self.num_variables, other.num_variables), terms, self.p)
        return ans

    __rmul__ = __mul__  # commutative

    def eval(self, at: List[int]) -> int:
        s = 0
        for term in self.terms:
            i = 0
            val = self.terms[term]
            while term != 0:
                if term & 1 == 1:
                    val = (val * (at[i] % self.p)) % self.p
                if val == 0:
                    break
                term >>= 1
                i += 1
            s = (s + val) % self.p

        return s

    def eval_bin(self, at: int) -> int:
        """
        Evaluate the polynomial where the arguments are in {0,1}. The ith argument is the ith bit of the polynomial.
        :param at: polynomial argument in binary form
        :return: polynomial evaluation
        """
        if at > 2 ** self.num_variables:
            raise ArithmeticError("Number of variables is larger than expected")
        args = [0 for _ in range(self.num_variables)]
        for i in range(self.num_variables):
            args[i] = at >> i & 1
        return self.eval(args)

    def __call__(self, *args, **kwargs) -> int:
        if len(args) == 0:
            return self.eval([])
        if isinstance(args[0], list):
            return self.eval(args[0])
        if isinstance(args[0], set):
            if len(args[0]) != 1:
                raise TypeError("Binary representation should have only one element. ")
            return self.eval_bin(next(iter(args[0])))
        return self.eval(list(args))

    def latex(self):
        s = ""
        for k in self.terms:
            s += " + "
            if self.terms[k] != 1:
                s += str(self.terms[k])

            i = 0
            while k != 0:
                if k & 1 == 1:
                    s += "x_{" + str(i) + "}"
                i += 1
                k >>= 1

        s = s[3:]
        display(Latex('$' + s + '$'))

    def __eq__(self, other: 'MVLinear') -> bool:
        diff = self - other
        return len(diff.terms) == 0  # zero polynomial

    def __getitem__(self, item):
        if item in self.terms.keys():
            return self.terms[item]
        else:
            return 0

    def eval_part(self, args: List[int]) -> 'MVLinear':
        """
        Evaluate part of the arguments of the multilinear polynomial.
        :param args: the arguments at beginning
        :return:
        """
        s = len(args)
        if s > self.num_variables:
            raise ValueError("len(args) > self.num_variables")
        new_terms: Dict[int, int] = dict()
        for t, v in self.terms.items():
            for k in range(s):
                if t & (1 << k) > 0:
                    v = v * (args[k] % self.p) % self.p
                    t = t & ~(1 << k)
            t_shifted = t >> s
            if t_shifted not in new_terms:
                new_terms[t_shifted] = 0
            new_terms[t_shifted] = (new_terms[t_shifted] + v) % self.p
        return MVLinear(self.num_variables - len(args), new_terms, self.p)

    def collapse_left(self, n: int) -> 'MVLinear':
        """
        Remove redundant unused variable from left.
        :param n: number of variables to collpse
        :return:
        """
        new_terms: Dict[int, int] = dict()
        mask = (1 << n) - 1
        for t, v in self.terms.items():
            if t & mask > 0:
                raise ArithmeticError("Cannot collapse: Variable exist. ")
            new_terms[t >> n] = v
        return MVLinear(self.num_variables - n, new_terms, self.p)

    def collapse_right(self, n: int) -> 'MVLinear':
        """
        Remove redundant unused variable from right.
        :param n: number of variables to collpse
        :return:
        """
        new_terms: Dict[int, int] = dict()
        mask = ((1 << n) - 1) << (self.num_variables - n)
        anti_mask = (1 << (self.num_variables - n)) - 1
        for t, v in self.terms.items():
            if t & mask > 0:
                raise ArithmeticError("Cannot collapse: Variable exist. ")
            new_terms[t & anti_mask] = v
        return MVLinear(self.num_variables - n, new_terms, self.p)

def makeMVLinearConstructor(num_variables: int, p: int) -> Callable[[Dict[int, int]], MVLinear]:
    """
    Return a function that outputs MVLinear
    :param num_variables: total number of variables
    :param p: size of the field
    :return: Callable[[Dict[int, int]], MVLinear]
    """

    def f(term: Dict[int, int]) -> MVLinear:
        return MVLinear(num_variables, term, p)

    return f


def randomMVLinear(num_variables: int, prime: int = 0, prime_bit_length: int = 128) -> MVLinear:
    num_terms = 2 ** num_variables
    prime = randomPrime(prime_bit_length) if prime == 0 else prime
    m = makeMVLinearConstructor(num_variables, prime)
    d: Dict[int, int] = dict()
    for _ in range(num_terms):
        d[random.randint(0, 2 ** num_variables - 1)] = random.randint(0, prime - 1)
    return m(d)


def randomPrime(size: int) -> int:
    return getPrime(size)