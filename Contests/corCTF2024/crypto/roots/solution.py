from decimal import Decimal, getcontext
from Crypto.Util.number import getPrime, bytes_to_long

getcontext().prec = 2024

p = getPrime(128)

print(Decimal(p).sqrt())
print(1 / (Decimal(p).sqrt() - Decimal(p).sqrt() // 1))
