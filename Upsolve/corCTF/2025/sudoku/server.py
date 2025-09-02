#!/usr/local/bin/python3

import json
import random
from commitment import *

FLAG = open("flag.txt").read()
NUM_ROUNDS = 2048 * 4 # this is sudoku, I swear!


def p2idx(row, col): # converts position to array index
    return row * 9 + col

def lit2idx(val): # converts a hard-coded number 0-9 to array index
    return 81 + val


game_constraints = set()

# sudoku constraints
for r in range(9):
    for c in range(9):
        # each cell must be different than all in its row and col
        this_idx = p2idx(r, c)
        game_constraints |= { (this_idx, p2idx(r, i)) for i in range(9) if i != c }
        game_constraints |= { (this_idx, p2idx(i, c)) for i in range(9) if i != r }
        # each cell must be different than all others in its 3x3
        zone_r = r // 3
        zone_c = c // 3
        this_zr = r % 3
        this_zc = c % 3
        game_constraints |= {
            (this_idx, p2idx(zone_r * 3 + zr, zone_c * 3 + zc))
            for zr in range(3)
            for zc in range(3)
            if zr != this_zr or zc != this_zc
        }

# clique of 9 sudoku numbers
for i in range(9):
    # each number must be different than all other numbers
    game_constraints |= { (lit2idx(i), lit2idx(j)) for j in range(9) if i != j }

PUZZLE_SPECIFIC_HINTS = [
    (p2idx(0, 3), 1-1), (p2idx(3, 0), 1-1),
    (p2idx(5, 8), 1-1), (p2idx(8, 5), 1-1),
    (p2idx(4, 4), 2-1)
] # four ones and a two are provided as hints

for idx, i in PUZZLE_SPECIFIC_HINTS:
    # make sure these cells must be unequal to all the other numbers
    game_constraints |= { (idx, lit2idx(j)) for j in range(9) if i != j }

# clean up the set to avoid doublets (a, b) and (b, a)
game_constraints = { (a, b) for a, b in game_constraints if a < b }


def main():
    print("I'll give you a flag if you can prove you have a solution for my sudoku,")
    print(f"testing your solution using {NUM_ROUNDS} rounds of verification.")
    print("Each round, commit a solution for the reduced 9-coloring vertex problem")
    print("of the 90-vertex sudoku graph, and I will choose an edge")
    print("to trivially test for consistency.\n")

    for i in range(NUM_ROUNDS):
        print(f"\nRound {i}:")
        print("Enter the committed graph, as a json list of strings:")
        user_graph = commitment_from_json(input())
        assert len(user_graph) == 90, "Invalid number of nodes"
        print("Also enter the names of the 9 colors you used:")
        user_colors = set(commitment_from_json(input()))
        assert len(user_colors) == 9, "Must use exactly 9 unique colors"

        a, b = random.choice(list(game_constraints))

        print(f"Verifing the edge ({a}, {b}).")
        print(f"Please reveal the commitments (in an ordered list):")
        user_reveal = reveal_from_json(input())
        assert len(user_reveal) == 2, "Invalid length for edge reveal"
        reveal_a, reveal_b = user_reveal
        assert verify_commitment(**reveal_a), "Invalid reveal"
        assert verify_commitment(**reveal_b), "Invalid reveal"

        assert reveal_a["color_name"] in user_colors, "Invalid commitment"
        assert reveal_b["color_name"] in user_colors, "Invalid commitment"

        assert reveal_a["commitment"] == user_graph[a], "Commitment mismatch"
        assert reveal_b["commitment"] == user_graph[b], "Commitment mismatch"

        assert reveal_a["color_name"] != reveal_b["color_name"], "Constraint violation"

        print("Round passed")
    else:
        print("\nAll rounds passed")
        print("You really did solve the sudoku, huh")
        print("Well, here's the flag:")
        print(FLAG)

if __name__ == "__main__":
    main()
