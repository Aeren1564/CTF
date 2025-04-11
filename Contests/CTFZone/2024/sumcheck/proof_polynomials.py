from collections import namedtuple

NUMBER_OF_POLYNOMIALS = 30
NUMBER_OF_COMMIITTED_POLYNOMIALS = 25
NUMBER_OF_VERIFICATION_KEY_POLYNOMIALS = 19
NUMBER_OF_INITIAL_WITNESS_POLYNOMIALS = 4
DERIVED_POLYNOMIALS = 2
POLYNOMIALS_WITH_SHIFT = 4
AllPolynomials = namedtuple(
    "AllPolynomials",
    [
        "lagrange_first",
        "lagrange_last",
        "q_lookup",
        "q_arith",
        "q_m",
        "q_l",
        "q_r",
        "q_o",
        "q_c",
        "id_l",
        "id_r",
        "id_o",
        "sigma_l",
        "sigma_r",
        "sigma_o",
        "table_0",
        "table_1",
        "table_2",
        "table_3",
        "w_l",
        "w_r",
        "w_o",
        "table_multiplicity",
        "permutation",
        "log_inverse",
        "permutation_shift",
        "w_l_shift",
        "w_r_shift",
        "w_o_shift",
        "zeta_powers",  # has to be last since we are not sending evaluation to the verifier
    ],
    defaults=[[] for _ in range(NUMBER_OF_POLYNOMIALS)],
)
