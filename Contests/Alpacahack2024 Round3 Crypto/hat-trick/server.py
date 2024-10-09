import json
import os
import random
import signal
import string
from Crypto.Util.number import getPrime, getRandomInteger

class RollingHash:
  def __init__(self, p=None, base=None) -> None:
    self.p = getPrime(64) if p is None else p
    self.base = (getRandomInteger(64) if base is None else base) % self.p
  def hash(self, s: str):
    res = 0
    for i, c in enumerate(s):
      res += ord(c) * (self.base ** i)
      res %= self.p
    return res

def check_str(s: str, max_len: int):
  assert len(s) <= max_len, "too long!"
  for i, c in enumerate(s):
    assert c in string.ascii_lowercase, f"found invalid char {c} at {i}"

signal.alarm(3 * 60)

flag = os.environ.get("FLAG", "fakeflag")
MAX_LEN = 54

rhs = [RollingHash() for _ in range(3)]
print("params:",json.dumps([{ "base": rh.base, "p": rh.p } for rh in rhs]))

for _ in range(3):
  target_hash = [random.randrange(0, rh.p) for rh in rhs]
  print('target:', target_hash)
  s = input("> ")
  check_str(s, MAX_LEN)

  actual_hash = [rh.hash(s) for rh in rhs]
  if target_hash != actual_hash:
    print("Oops! You missed the target hash. Better luck next time!")
    exit(1)

print("Congratulations! Here is your flag:", flag)
