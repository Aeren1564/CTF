## Manhattan Subgraph

You have a big cube consisting on $n^3$ cubes, disposed in a $n \times n \times n$ fashion.

Each cube can be painted in white or black.

It is guaranteed that the black cubes are face-connected, that is, for every pairs of black cubes $A,B$ there is a sequence of cubes starting at $A$ and ending at $B$ on which every adjacent pair of cubes shares a face.

It is also guaranteed that there is a black cube in each face of the big cube.

Thus, we consider the vertices of these cubes, which form a $(n+1) \times (n+1) \times (n+1)$ grid. These vertices will be the vertices of our new graph.

For every black cube, we consider its edges, and add them to the graph. Then, we will permute the graph and give it to you.

Your task is to recover the initial configuration of black cubes for all testcases (present in testcases.py), and write them in the file solution.py, following the description in example/solution.py.

\textbf{It is also guaranteed that for any given input, the answer will contain the maximum possible amount of black cubes.}

Since there may be more than one possible solution, we give you a file (checker.py) that automatically checks whether all answers have the correct SHA1 hash, and if they are, will automatically decrypt the ciphertext and give you the flag.

