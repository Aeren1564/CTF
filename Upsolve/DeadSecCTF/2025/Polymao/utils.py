from py_ecc import bls12_381
from py_ecc.bls.point_compression import compress_G1, decompress_G1, compress_G2, decompress_G2
from polynomial_evalrep import get_omega, polynomialsEvalRep
from ssbls12 import Fp, Poly, Group, SS_BLS12_381
from ast import literal_eval

def eval_poly_coeffs(coeffs, xs):
    ys = []
    for x in xs:
        cur = 0
        for c in coeffs:
            cur = cur*x + c
        ys.append(cur)
    return ys
 
def poly_from_str(s, n=None):
    coeffs = s.split(' + ')
    coeffs = [Fp(x.split(' ')[0]) for x in coeffs]
    if not n:
        n = len(coeffs)
    poly = Poly(coeffs)
    
    omega_base = get_omega(Fp, 2 ** 32, seed=0)
    omega = omega_base ** (2 ** 32 // n)
    PolyEvalRep = polynomialsEvalRep(Fp, omega, n)
    return PolyEvalRep.from_coeffs(poly)    

# Actually Group_to_str and Group_from_str.
def Group_to_hex(g: Group) -> str:
    # return str((G1_to_hex(g.m1)), (G2_to_hex(g.m2)))
    return str((compress_G1(g.m1), compress_G2(g.m2)))


def Group_from_hex(s) -> Group:
    if type(s) != str:
        s = str(s)
    # sp = s.split(',', 1)
    # return Group(G1_from_hex(sp[0]), G2_from_hex(sp[1]))
    s2 = literal_eval(s)
    return Group(decompress_G1(s2[0]), decompress_G2(s2[1]))

def convert_proof_elements(raw_proof_SNARK):
    """
    Converts all elements within a raw_proof_SNARK tuple to their
    corresponding SS_BLS12_381 or Fp types based on the verifier_algo
    structure and type assertions.

    Args:
        raw_proof_SNARK (tuple): The proof tuple with elements as raw
                                 integers or (m1, m2) tuples.
                                 Expected structure:
                                 (first_output, second_output, third_output,
                                  fifth_output, fourth_output)
                                 where:
                                 - first_output: ((m1,m2), (m1,m2), (m1,m2))
                                 - second_output: (m1,m2)
                                 - third_output: ((m1,m2), (m1,m2), (m1,m2))
                                 - fifth_output: ((m1,m2), (m1,m2))
                                 - fourth_output: (int, int, ..., int)

    Returns:
        tuple: The converted proof_SNARK tuple with elements as SS_BLS12_381
               or Fp instances.
    """
    # Unpack the raw proof according to verifier_algo's structure
    # Note the order: first, second, third, fifth, fourth
    raw_first_output, raw_second_output, raw_third_output, raw_fifth_output, raw_fourth_output = raw_proof_SNARK

    # Convert first_output elements to SS_BLS12_381
    # Assumes each element in raw_first_output is a (m1, m2) tuple
    a_eval_exp = Group_from_hex(raw_first_output[0])
    b_eval_exp = Group_from_hex(raw_first_output[1])
    c_eval_exp = Group_from_hex(raw_first_output[2])
    first_output = [a_eval_exp, b_eval_exp, c_eval_exp]

    for pt in first_output:
        assert pt.in_group()

    # Convert second_output element to SS_BLS12_381
    # Assumes raw_second_output is a single (m1, m2) tuple
    z_eval_exp = Group_from_hex(raw_second_output)
    second_output = z_eval_exp

    assert second_output.in_group()

    # Convert third_output elements to SS_BLS12_381
    # Assumes each element in raw_third_output is a (m1, m2) tuple
    t_lo_eval_exp = Group_from_hex(raw_third_output[0])
    t_mid_eval_exp = Group_from_hex(raw_third_output[1])
    t_hi_eval_exp = Group_from_hex(raw_third_output[2])
    third_output = [t_lo_eval_exp, t_mid_eval_exp, t_hi_eval_exp]

    for pt in third_output:
        assert pt.in_group()

    # Convert fifth_output elements to SS_BLS12_381
    # Assumes each element in raw_fifth_output is a (m1, m2) tuple
    W_zeta_eval_exp = Group_from_hex(raw_fifth_output[0])
    W_zeta_omega_eval_exp = Group_from_hex(raw_fifth_output[1])
    fifth_output = [W_zeta_eval_exp, W_zeta_omega_eval_exp]

    for pt in fifth_output:
        assert pt.in_group()

    # Convert fourth_output elements to Fp
    # Assumes each element in raw_fourth_output is an integer
    a_zeta = Fp(raw_fourth_output[0])
    b_zeta = Fp(raw_fourth_output[1])
    c_zeta = Fp(raw_fourth_output[2])
    S_1_zeta = Fp(raw_fourth_output[3])
    S_2_zeta = Fp(raw_fourth_output[4])
    accumulator_shift_zeta = Fp(raw_fourth_output[5])
    t_zeta = Fp(raw_fourth_output[6])
    r_zeta = Fp(raw_fourth_output[7])
    fourth_output = [a_zeta, b_zeta, c_zeta, S_1_zeta, S_2_zeta, accumulator_shift_zeta, t_zeta, r_zeta]

    # Reconstruct the proof_SNARK tuple in the original order (first, second, third, fifth, fourth)
    converted_proof_SNARK = [first_output, second_output, third_output, fifth_output, fourth_output]

    return converted_proof_SNARK