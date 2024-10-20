import os
import secrets

FLAG = os.environ.get("FLAG", "flag{local_solve_successful}")

MASTER_KEY_SIZE = 130
MASTER_KEY = secrets.randbits(MASTER_KEY_SIZE*8).to_bytes(MASTER_KEY_SIZE)

