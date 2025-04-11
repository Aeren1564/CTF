import signal
import struct
import subprocess
import os
import sys
import tempfile

MASK = 0xFFFFFFFFFFFFFFFF
p64 = lambda x: struct.pack("<Q", x)

signal.alarm(30)

if input("password from part 1: ").strip() != "oaq1MD92evRsDZvH":
    print("wrong")
    sys.exit(1)

s0 = int(input("s0: ")) & MASK
s1 = int(input("s1: ")) & MASK

if s0 == 0 and s1 == 0:
    print("bad")
    sys.exit(1)

maximum = int(input("maximum: "))

if not 0 <= maximum <= 4600000000000000:
    print("bad")
    sys.exit(1)

# the d8 and node binaries are taken from the part 1 docker image (excav8)
with open("d8", "rb") as f:
    d8 = bytearray(f.read())
with open("node", "rb") as f:
    node = bytearray(f.read())

# patch MathRandom::RefillCache
d8[0x917E8E : 0x917E8E + 10] = b"\x49\xbe" + p64(s0)  # mov r14, s0
d8[0x917E8E + 10 : 0x917E8E + 20] = b"\x48\xb9" + p64(s1)  # mov rcx, s1
d8[0x917E8E + 20 : 0x917E8E + 23] = b"\x48\x89\xc8"  # mov rax, rcx

node[0x127497A : 0x127497A + 10] = b"\x49\xbe" + p64(s0)  # mov r14, s0
node[0x127497A + 10 : 0x127497A + 20] = b"\x48\xb9" + p64(s1)  # mov rcx, s1
node[0x127497A + 20 : 0x127497A + 23] = b"\x90" * 3

d8_patched = tempfile.NamedTemporaryFile(delete_on_close=False)
d8_patched.write(bytes(d8))
d8_patched.close()
os.chmod(d8_patched.name, 0o755)

node_patched = tempfile.NamedTemporaryFile(delete_on_close=False)
node_patched.write(bytes(node))
node_patched.close()
os.chmod(node_patched.name, 0o755)

d8_output = subprocess.check_output([d8_patched.name, "gen.js", "--", str(maximum)])
d8_ints = [int(i) for i in d8_output.strip().split()]
node_output = subprocess.check_output([node_patched.name, "gen.js", str(maximum)])
node_ints = [int(i) for i in node_output.strip().split()]

mismatches = 0
for x, y in zip(d8_ints, node_ints):
    if x != y:
        mismatches += 1

if mismatches >= 104:
    print("good!")
    print(open("flag.txt").read().strip())
else:
    print("not good")
