import random, os;
flag = os.urandom(random.randrange(0,1337)) + open("flag.txt", "rb").read() + os.urandom(random.randrange(0,1337));
random.seed(flag);
assert random.getstate()[1][0] == 2147483648
assert len(flag) < 1337*1.337
print(''.join(map(str, [random.getrandbits(1) for _ in range(20219)])))
