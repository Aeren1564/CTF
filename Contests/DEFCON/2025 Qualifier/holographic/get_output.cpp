// #include <bits/allocator.h> // Temp fix for gcc13 global pragma
// #pragma GCC target("avx2,bmi2,popcnt,lzcnt")
// #pragma GCC optimize("O3,unroll-loops")
#include <bits/stdc++.h>
// #include <x86intrin.h>
using namespace std;
#if __cplusplus >= 202002L
using namespace numbers;
#endif

// Custom implementation of the Mersenne Twister initialization
std::vector<uint32_t> initMTState(uint32_t seed1, uint32_t seed2) {
    const size_t STATE_SIZE = 624;
    std::vector<uint32_t> state(STATE_SIZE, 0x8b8b8b8b);
    uint32_t seedData[2] = {seed1, seed2};
    
    size_t stateSize = STATE_SIZE;
    size_t seedSize = 2;
    size_t skip = 11;
    
    // Calculate half and other parameters
    size_t half = (stateSize - skip) >> 1;
    
    // Initial state setup
    state[half] += 0x51BF72D2;
    state[half] &= 0xffffffff;
    
    uint32_t seedSum = seedSize + 0x51BF72D2;
    seedSum &= 0xffffffff;
    
    state[half + skip] += seedSum;
    state[half + skip] &= 0xffffffff;
    
    state[0] = seedSum;
    
    // Determine loop length
    size_t loopLen = (seedSize < 3) ? 2 : seedSize;
    loopLen--;
    
    size_t pos1 = half + skip + 1;
    size_t pos2 = half + 1;
    
    // First mixing phase
    for (size_t i = 0; i < loopLen; i++) {
        size_t idx1 = (i + 1) % stateSize;
        size_t idx2 = (pos2 + i) % stateSize;
        size_t idx3 = (i + pos1) % stateSize;
        size_t idx0 = i % stateSize;
        
        uint32_t val2 = state[idx2];
        uint32_t xorVal = state[idx0] ^ val2 ^ state[idx1] ^ ((state[idx0] ^ val2 ^ state[idx1]) >> 27);
        uint32_t newVal = 1664525 * xorVal;
        newVal &= 0xffffffff;
        
        uint32_t val3 = newVal + idx1 + seedData[i];
        val3 &= 0xffffffff;
        
        state[idx2] = newVal + val2;
        state[idx2] &= 0xffffffff;
        
        state[idx3] += val3;
        state[idx3] &= 0xffffffff;
        
        state[idx1] = val3;
        state[idx1] &= 0xffffffff;
    }
    
    // Second mixing phase
    for (size_t i = seedSize; i < stateSize; i++) {
        size_t idx0 = (i - 1) % stateSize;
        size_t idx1 = i % stateSize;
        size_t idx2 = (half + i) % stateSize;
        size_t idx3 = (i + skip + half) % stateSize;
        
        uint32_t val2 = state[idx2];
        uint32_t xorVal = state[idx0] ^ val2 ^ state[idx1] ^ ((state[idx0] ^ val2 ^ state[idx1]) >> 27);
        uint32_t newVal = 0x19660D * xorVal; // 1664525 in decimal
        newVal &= 0xffffffff;
        
        state[idx2] = newVal + val2;
        state[idx2] &= 0xffffffff;
        
        state[idx3] += idx1 + newVal;
        state[idx3] &= 0xffffffff;
        
        state[idx1] = idx1 + newVal;
        state[idx1] &= 0xffffffff;
    }
    
    // Third mixing phase
    for (size_t i = 0; i < stateSize; i++) {
        size_t idx0 = (stateSize + i - 1) % stateSize;
        size_t idx1 = (stateSize + i) % stateSize;
        size_t idx2 = (half + stateSize + i) % stateSize;
        size_t idx3 = (stateSize + i + skip + half) % stateSize;
        
        uint32_t val2 = state[idx2];
        uint32_t sum = state[idx0] + val2 + state[idx1];
        sum &= 0xffffffff;
        
        uint32_t xorVal = sum ^ (sum >> 27);
        uint32_t newVal = 0x5d588b65 * xorVal; // 1566083941 in decimal
        newVal &= 0xffffffff;
        
        uint32_t val4 = newVal ^ val2;
        val4 &= 0xffffffff;
        
        uint32_t val5 = newVal - idx1;
        val5 &= 0xffffffff;
        
        state[idx2] = val4;
        state[idx2] &= 0xffffffff;
        
        state[idx3] ^= val5;
        state[idx3] &= 0xffffffff;
        
        state[idx1] = val5;
        state[idx1] &= 0xffffffff;
    }
    
    return state;
}

// Custom MT19937 implementation that can be initialized from a custom state
class CustomMT19937 {
private:
    static const size_t N = 624;
    static const size_t M = 397;
    static const uint32_t MATRIX_A = 0x9908b0df;
    static const uint32_t UPPER_MASK = 0x80000000;
    static const uint32_t LOWER_MASK = 0x7fffffff;
    
    uint32_t mt[N];
    size_t mti;

public:
    // Default constructor
    CustomMT19937() : mti(N+1) {
        seed(5489u);  // Default seed
    }
    
    // Set seeds using our custom initialization
    void setSeedsCustom(uint32_t s1, uint32_t s2) {
        std::vector<uint32_t> state = initMTState(s1, s2);
        for (size_t i = 0; i < N; i++) {
            mt[i] = state[i];
        }
        mti = 0;
    }
    
    // Initialize with single seed (standard method)
    void seed(uint32_t s) {
        mt[0] = s;
        for (mti = 1; mti < N; mti++) {
            mt[mti] = 1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti;
        }
    }
    
    // Set state from array
    void setState(const uint32_t* state) {
        for (size_t i = 0; i < N; i++) {
            mt[i] = state[i];
        }
        mti = 0;
    }
    
    // Generate a random number
    uint32_t operator()() {
        uint32_t y;
        static const uint32_t mag01[2] = {0x0UL, MATRIX_A};
        
        // Generate N words at a time
        if (mti >= N) {
            // If seed() has not been called, initialize with default seed
            if (mti == N+1) seed(5489u);
            
            for (size_t kk = 0; kk < N-M; kk++) {
                y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
                mt[kk] = mt[kk+M] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            for (size_t kk = N-M; kk < N-1; kk++) {
                y = (mt[kk] & UPPER_MASK) | (mt[kk+1] & LOWER_MASK);
                mt[kk] = mt[kk+(M-N)] ^ (y >> 1) ^ mag01[y & 0x1UL];
            }
            y = (mt[N-1] & UPPER_MASK) | (mt[0] & LOWER_MASK);
            mt[N-1] = mt[M-1] ^ (y >> 1) ^ mag01[y & 0x1UL];
            
            mti = 0;
        }
        
        y = mt[mti++];
        
        // Tempering
        y ^= (y >> 11);
        y ^= (y << 7) & 0x9d2c5680UL;
        y ^= (y << 15) & 0xefc60000UL;
        y ^= (y >> 18);
        
        return y;
    }
};

// Shuffle deck of cards using MT19937
void shuffleDeck(array<int, 52> &deck, int size, CustomMT19937& rng) {
    for (int i = size - 1; i > 0; i--) {
        int j = rng() % (i + 1);
        std::swap(deck[i], deck[j]);
    }
}

array<int, 52> shuffle(unsigned int env_seed, unsigned int seed){
	array<int, 52> deck;
	ranges::iota(deck, 0);
    // Initialize our custom MT19937 with these seeds
  CustomMT19937 rng;
  rng.setSeedsCustom(env_seed, seed);
  
  // Print the initial state of the MT
  std::vector<uint32_t> initialState = initMTState(env_seed, seed);
  
  // Shuffle the deck
  shuffleDeck(deck, 52, rng);
	return deck;
}

int main(){
	ifstream fin("input.txt");
	string cur;
	assert(getline(fin, cur));
	istringstream iss(cur);
	unsigned int env_seed;
	unsigned int seed;
	iss >> env_seed >> seed;
	auto deck = shuffle(env_seed, seed);
	ofstream fout("output.txt");
	ranges::copy(deck, ostream_iterator<int>(fout, " "));
	fout << "\n";
	return 0;
}

/*

*/