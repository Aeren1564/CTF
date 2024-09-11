from Crypto.Util.number import *
from os import urandom
import random
from secret import flag

def padding(flag,length):
    head_length = random.randint(1,length-len(flag))
    tail_length = length-len(flag)-head_length
    while 1:
        re = urandom(head_length)+flag+urandom(tail_length)
        if (bin(bytes_to_long(re)).count('1')) % 2:
            return re

def shuffle(left,right):
    xor_string = [0]*left+[1]*right
    random.shuffle(xor_string)
    xor_string = int(''.join(str(i) for i in xor_string),2)
    return xor_string

l,r = 63,65
flag = padding(flag,(len(flag)//4+1)*4)
S = [bytes_to_long(padding(flag[len(flag)//4*i:len(flag)//4*(i+1)],(l+r)//8)) for i in range(4)]
data = [[[shuffle(r,l)^^S[_] if j == '1' else shuffle(l,r)^^S[_] for j in (bin(shuffle(r,l)^^S[_])[2:].rjust(l+r,'0') if i == '1' else bin(shuffle(l,r)^^S[_])[2:].rjust(l+r,'0'))] for i in bin(S[_])[2:].rjust(l+r,'0')] for _ in range(4)]

print(data)