#!/usr/local/bin/python3
inp = input("> ")

for i, v in enumerate(inp):
    if not (ord(v) < 128 and i % 2 == ord(v) % 2):
        print(f'bad, {i = }, {ord(v) = }, {v.encode() = }')
        print(f"{inp[i : ] = }")
        exit()

eval(inp)
