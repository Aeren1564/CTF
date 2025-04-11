from CTF_Library import *
import secrets
from uov import uov_1p_pkc as uov
uov.set_random(secrets.token_bytes)

print(f"{uov.n_sz = }")
print(f"{uov.m_sz = }")