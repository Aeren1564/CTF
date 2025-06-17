POLY = 0xb797d18eb0f60066397496ea1d8ba42751c8b9a8e9fc1d3cacc6eb89c562bec5c18befe0ae511d311bb582077550b507035c1833746d6aa15391ab336ab2449f712a280c89c87a6a4c90a1865940813c23db3f6a421eef9d77acaf5a1bd06077d26149cabb59728e12fa84c087c5743180d8e3495eb0efb770c3b7b5cdedb0b18f70134c0a3c8a11a7ed7d2ec27a6f6f5f06610e172d7c45a9d214fe5081740f5c7af4688652135e2e2b9b57695d09a6624e69e287a8ef6a5d2eba6eda3ba270b163ce15330be6332203cc66e135f33111f16a6d492242ff73cc649738bbc5810dc2dcffd02b75d822dd06f611ea2bf91d309daf3a34f8773d4517bccb76760cabef4e3b2c399169d93211866966c45becd572f

class RandomNumberGenerator:

    def __init__(self, seed: int, poly = POLY):
        self._poly = poly
        self._seed = seed
        assert seed.bit_length() < poly.bit_length(), f"{seed.bit_length()} >= {poly.bit_length()}"
        self._state = seed
        for _ in range(8192):
            self.clock()

    def clock(self):
        self._state <<= 1
        if self._state.bit_length() == self._poly.bit_length():
            self._state ^= self._poly
            return 1
        return 0

    def getbits(self, bits: int = 1):
        assert isinstance(bits, int) and bits > 0
        result = 0
        for _ in range(bits):
            result <<= 1
            result ^= self.clock()
        return result


from .keccak import Keccak
