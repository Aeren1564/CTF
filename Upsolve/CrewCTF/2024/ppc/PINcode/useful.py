def makepin(n,b):
  return n < len(b) and b[n] or makepin(n // len(b), [c for c in digits if c != b[n % len(b)]]) + b[n % len(b)]

digits = "123A456B789C*0#D"

assert(len(FLAG) == 262)

pin = makepin(int.from_bytes(FLAG, 'big'), digits)[::-1]
