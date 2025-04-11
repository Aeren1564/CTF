import subprocess

secret = open('secret.txt').read().strip()
secretbits = ''.join(f'{ord(i):08b}' for i in secret)

output = []

for bit in secretbits:
    if bit == '0':
        output += [float(i) for i in subprocess.check_output('./d8 gen.js', shell=True).decode().split()]
    else:
        output += [float(i) for i in subprocess.check_output('node gen.js', shell=True).decode().split()]

for i in output:
    print(i)
