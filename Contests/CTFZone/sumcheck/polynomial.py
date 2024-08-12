import random
from ff import Fr
import copy
import unittest


def batch_polynomials(polynomials, batching_scalar, starting_scalar=Fr(1)):
    if len(polynomials) == 0:
        return []
    polynomial_length = len(polynomials[0])
    for i in range(1, len(polynomials)):
        assert polynomial_length == len(polynomials[i])
    batched_polynomial = [
        Fr(polynomials[0][i]) * starting_scalar for i in range(polynomial_length)
    ]
    current_power = starting_scalar * batching_scalar
    for i in range(1, len(polynomials)):
        current_polynomial = polynomials[i]
        for j in range(polynomial_length):
            batched_polynomial[j] += current_power * current_polynomial[j]
        current_power *= batching_scalar
    return batched_polynomial


def batch_inverse(polynomial):
    products = [Fr(1)]

    for x in polynomial:
        products.append(products[-1] * x)

    running_inverse = products[-1].invert()
    inverses = []
    for i in range(len(products) - 2, -1, -1):
        inverses.insert(0, running_inverse * products[i])
        running_inverse *= polynomial[i]
    return inverses


def vanishing_polynomial_on_domain(domain: list[Fr]):
    vanishing_poly = [Fr(1)]
    for i in range(0, len(domain)):
        new_vanishing_poly = [Fr(0) for j in range(i + 2)]
        for j in range(1, i + 2):
            new_vanishing_poly[j] += vanishing_poly[j - 1]
            new_vanishing_poly[j - 1] -= vanishing_poly[j - 1] * domain[i]
        vanishing_poly = new_vanishing_poly
    return vanishing_poly


def divide_polynomial_by_known_root(polynomial: list[Fr], root: Fr):
    if root == 0:
        assert polynomial[0] == 0
        return polynomial[1:]
    current_remainder = polynomial[0]
    quotient_polynomial = []
    q_s = Fr(0)
    root_inverse = root.invert()
    for i in range(1, len(polynomial)):
        multiplicand = -current_remainder * root_inverse
        q_s += multiplicand
        quotient_polynomial.append(multiplicand)
        current_remainder = polynomial[i] - multiplicand
    assert current_remainder == Fr(0)
    return quotient_polynomial


def convert_from_lagrange_to_monomial_form(polynomial_in_evaluation_form: list[Fr]):
    h_x = vanishing_polynomial_on_domain(
        [Fr(i) for i in range(len(polynomial_in_evaluation_form))]
    )
    final_polynomial = [Fr(0) for _ in range(len(polynomial_in_evaluation_form))]
    for i, coeff in enumerate(polynomial_in_evaluation_form):
        partial_h_x = divide_polynomial_by_known_root(h_x, Fr(i))
        p_h_x_at_i = evaluate_polynomial(partial_h_x, Fr(i))
        multiplicand = coeff / p_h_x_at_i
        for j in range(len(final_polynomial)):
            final_polynomial[j] += partial_h_x[j] * multiplicand

    return final_polynomial


def evaluate_polynomial(polynomial_in_monomial_form, evaluation_point):
    start = Fr(0)
    for i in range(len(polynomial_in_monomial_form) - 1, -1, -1):
        start *= evaluation_point
        start += polynomial_in_monomial_form[i]
    return start


def partially_evaluate_multilinear_polynomial(polynomial, evaluation_point):
    new_polynomial = []
    for i in range(0, len(polynomial), 2):
        difference = polynomial[i + 1] - polynomial[i]
        new_polynomial.append(polynomial[i] + difference * evaluation_point)
    return new_polynomial


def evaluate_multilinear_polynomial(polynomial, evaluation_points):
    assert len(polynomial) == (1 << len(evaluation_points))
    if len(polynomial) == 1:
        return polynomial[0]
    return evaluate_multilinear_polynomial(
        partially_evaluate_multilinear_polynomial(polynomial, evaluation_points[0]),
        evaluation_points[1:],
    )


def compute_quotient(polynomial, evaluation_point, evaluation):
    new_polynomial = copy.deepcopy(polynomial)
    new_polynomial[0] -= evaluation
    return divide_polynomial_by_known_root(new_polynomial, evaluation_point)


class PolynomialTest(unittest.TestCase):
    def test_vanishing_polynomial(self):
        domain = []
        for i in range(10):
            domain.append(Fr.from_bytes(random.randbytes(32)))
        h_x = vanishing_polynomial_on_domain(domain)
        at_least_one_nonzero = False
        for el in h_x:
            at_least_one_nonzero = at_least_one_nonzero or el != Fr(0)
        self.assertTrue(at_least_one_nonzero)
        for el in domain:
            self.assertEqual(evaluate_polynomial(h_x, el), Fr(0))
        quotient = h_x
        for el in domain:
            quotient = divide_polynomial_by_known_root(quotient, el)
        self.assertEqual(quotient[0], 1)
        self.assertEqual(len(quotient), 1)

    def test_monomial_from_evaluations(self):
        coeffs = [Fr(i) for i in range(10)]
        monomial = convert_from_lagrange_to_monomial_form(coeffs)
        for i in range(10):
            self.assertEqual(evaluate_polynomial(monomial, Fr(i)), coeffs[i])

        coeffs = [Fr.from_bytes(random.randbytes(32)) for i in range(20)]
        monomial = convert_from_lagrange_to_monomial_form(coeffs)
        for i in range(10):
            self.assertEqual(evaluate_polynomial(monomial, Fr(i)), coeffs[i])


if __name__ == "__main__":
    unittest.main()
