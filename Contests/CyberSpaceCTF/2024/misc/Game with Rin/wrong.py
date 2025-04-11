from pwn import *


#r = remote("game-with-rin.challs.csc.tf",1337)
r = process(["python3", "server.py"])

#r.interactive()

for i in range(100):
    print(f"Round #{i}")
    out = r.recvuntil(b"You> ").decode()
    print(f"Out : {out} ....")
    f = out.split("edges = [(")[1].split(",")[0]
    res = f"{f} {f}"
    print(f"res, {res}")
    r.sendline(b"second")
    # print(r.clean(2).decode())
    print(r.recvuntil(b"You> T = "))
    print(f"Check 1")
    r.sendline(res.encode())
    print(f"Check 2")

