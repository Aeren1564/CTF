from transcript import Transcript
from params import params
import random
class ZKP:
    def __init__(self, params=params):
        self.transcript = Transcript()
        params._set(self)

    def indices(self, dl, n):
        x = random.Random(self.transcript.get_challenge())
        indices = []
        used = []
        while len(used) != n:
            idx = x.randint(0, dl - 1)
            if idx % self.expansion_factor not in used:
                indices.append(idx)
                used.append(idx % self.expansion_factor)
        return indices