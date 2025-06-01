#!/usr/bin/env python3

from random import *
from secret import FLAG

N = 2**32
times = 64
r = .1
h1 = 'your number is too big'
h2 = 'your number is too small'
h3 = 'you win'
print("=== Welcome to D3CTF 2025 ===")
print("You have at most 1 hour to solve this challenge.")
print("Can you defeat the biased oracle?\n")
rr = Random()

def challge(rounds, times, N, r, mode=0):
	wins = 0
	f = lambda x: [0.075, 0.15, 0.225, 0.3, 0.375, 0.45][5 - x * 6 // 2**32]
	print(["Now let's play a simple number-guessing game", "Let's play a relatively simple number-guessing game again"][mode])
	for round_idx in range(rounds):
		x = rr.randint(1, N - 1)
		print(f"[*] Starting Round {round_idx + 1} of {rounds}")
		for _ in range(times):
			try:
				guess = int(input(f'[d3ctf@oracle] {x} give me a number > '))
			except:
				print("[!] Invalid input detected. Session terminated.")
				exit()
			if guess > x:
				print([f(abs(guess - x)), [h1, h2][rr.random() < r]][mode])
			elif guess < x:
				print([f(abs(guess - x)), [h2, h1][rr.random() < r]][mode])
			else: 
				print(h3)
				wins += 1
				break
	return wins

if challge(350, 32, N, r) == 350 and challge(2200, 64, N, r, mode=1) > 2112:
	print(f"[!] You have proven your power over probability. This is your {FLAG}. Congratulations!")
else:
	print("[X] The oracle remains unbeaten. Try again, challenger.")
	exit()
