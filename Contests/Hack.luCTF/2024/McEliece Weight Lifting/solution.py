from CTF_Library import *
from pathlib import Path

pk = json.loads(Path("data/pubkey").read_text())

print(f"{pk.keys() = }")
print(len(pk['P']))
print(len(pk['P'][0]))
print(len(pk['P'][-1]))