#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <random>
#include <vector>
#include <algorithm>

// Constants for MT19937
constexpr size_t N = 624;                // State size
constexpr size_t M = 397;                // Shift size
constexpr uint32_t MATRIX_A = 0x9908b0df;  // Constant vector a
constexpr uint32_t UPPER_MASK = 0x80000000;  // Most significant bit
constexpr uint32_t LOWER_MASK = 0x7fffffff;  // Least significant bits

// Custom MT19937 implementation that can be initialized from a custom state
class CustomMT19937 {
private:
    uint32_t mt[N];      // State vector
    size_t mti;          // Index

public:
    // Default constructor
    CustomMT19937() : mti(N+1) {
        seed(5489u);  // Default seed
    }

    // Constructor with seed
    CustomMT19937(uint32_t s) : mti(N+1) {
        seed(s);
    }

    // Set seed
    void seed(uint32_t s) {
        mt[0] = s;
        for (mti = 1; mti < N; mti++) {
            mt[mti] = 1812433253UL * (mt[mti-1] ^ (mt[mti-1] >> 30)) + mti;
        }
    }

    // Initialize from custom state
    void setState(const uint32_t* state) {
        std::memcpy(mt, state, N * sizeof(uint32_t));
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

    // Get min value
    uint32_t min() const {
        return 0;
    }

    // Get max value
    uint32_t max() const {
        return 0xffffffff;
    }
};

// Convert card string (like "sA") to integer index
int convertCardToInt(const std::string& card) {
    if (card.length() < 2) return -1;
    
    char suit = card[0];
    char value = card[1];
    
    int suit_index = 0;
    if (suit == 'h') suit_index = 1;
    else if (suit == 'c') suit_index = 2;
    else if (suit == 'd') suit_index = 3;
    else if (suit != 's') return -1;
    
    int value_index = 0;
    if (value == '2') value_index = 1;
    else if (value == '3') value_index = 2;
    else if (value == '4') value_index = 3;
    else if (value == '5') value_index = 4;
    else if (value == '6') value_index = 5;
    else if (value == '7') value_index = 6;
    else if (value == '8') value_index = 7;
    else if (value == '9') value_index = 8;
    else if (value == 'X') value_index = 9;
    else if (value == 'J') value_index = 10;
    else if (value == 'Q') value_index = 11;
    else if (value == 'K') value_index = 12;
    else if (value != 'A') return -1;
    
    return suit_index * 13 + value_index;
}

// Convert integer index to card string (like "sA")
std::string convertIntToCard(int card) {
    const char suits[] = "shcd";
    const char values[] = "A234567890JQK";
    
    int suit = card / 13;
    int value = card % 13;
    char display_value = values[value];
    if (value == 9) display_value = 'X'; // Use X for 10
    
    return std::string(1, suits[suit]) + std::string(1, display_value);
}

// Custom initialization for Mersenne Twister
void customMTMixing(const std::vector<uint32_t>& seedData, uint32_t* state, size_t stateCount) {
    if (seedData.empty() || !state || stateCount < N) return;
    
    // Initialize buffer with pattern
    memset(state, 139, stateCount * sizeof(uint32_t));
    
    size_t len = stateCount;
    size_t skip = 11;
    
    // Adjust skip value based on length
    if (len <= 0x9B8 / 4) {
        skip = 7;
        if (len <= 0x10C / 4) {
            skip = 5;
            if (len <= 0x98 / 4) {
                skip = 3;
                if (len <= 0x18 / 4)
                    skip = (len - 1) >> 1;
            }
        }
    }
    
    size_t half = (len - skip) >> 1;
    size_t seedLen = seedData.size();
    
    // Initial state manipulation
    state[half] += 1371501266;
    int val = seedLen + 1371501266;
    state[half + skip] += val;
    state[0] = val;
    
    // First mixing loop
    size_t start = 1;
    size_t loopLen = (seedLen < 3) ? 2 : seedLen;
    loopLen--;
    
    size_t pos1 = half + skip + 1;
    size_t pos2 = half + 1;
    
    for (size_t i = 0; i < loopLen; i++) {
        size_t idx1 = (i + 1) % len;
        size_t idx2 = (pos2 + i) % len;
        size_t idx3 = (i + pos1) % len;
        size_t idx0 = i % len;
        
        uint32_t val2 = state[idx2];
        uint32_t xorVal = state[idx0] ^ val2 ^ state[idx1] ^ ((state[idx0] ^ val2 ^ state[idx1]) >> 27);
        uint32_t newVal = 1664525 * xorVal;
        int val3 = newVal + idx1 + seedData[i];
        
        state[idx2] = newVal + val2;
        state[idx3] += val3;
        state[idx1] = val3;
    }
    
    // Second mixing loop
    for (size_t i = seedLen; i < len; i++) {
        size_t idx0 = (i - 1) % len;
        size_t idx1 = i % len;
        size_t idx2 = (half + i) % len;
        size_t idx3 = (i + skip + half) % len;
        
        uint32_t val2 = state[idx2];
        uint32_t xorVal = state[idx0] ^ val2 ^ state[idx1] ^ ((state[idx0] ^ val2 ^ state[idx1]) >> 27);
        uint32_t newVal = 1664525 * xorVal;
        
        state[idx2] = newVal + val2;
        state[idx3] += idx1 + newVal;
        state[idx1] = idx1 + newVal;
    }
    
    // Third mixing loop
    for (size_t i = len; i < len * 2; i++) {
        size_t idx0 = (i - 1) % len;
        size_t idx1 = i % len;
        size_t idx2 = (half + i) % len;
        size_t idx3 = (i + skip + half) % len;
        
        uint32_t val2 = state[idx2];
        uint32_t sum = state[idx0] + val2 + state[idx1];
        uint32_t xorVal = sum ^ (sum >> 27);
        uint32_t newVal = 1566083941 * xorVal;
        
        state[idx2] = newVal ^ val2;
        state[idx3] ^= newVal - idx1;
        state[idx1] = newVal - idx1;
    }
}

// Display all cards in a deck
void displayDeck(const int* deck, int size) {
    for (int i = 0; i < size; i++) {
        std::cout << convertIntToCard(deck[i]) << " ";
    }
    std::cout << std::endl;
}

// Shuffle deck using custom MT19937
void shuffleDeck(int* deck, int size, CustomMT19937& rng) {
    for (int i = size - 1; i > 0; i--) {
        int j = rng() % (i + 1);
        std::swap(deck[i], deck[j]);
    }
}

// Get flag from environment or file
std::string getFlag() {
    const char* env_flag = std::getenv("FLAG");
    if (env_flag) {
        return env_flag;
    }
    
    const char* flag_file = std::getenv("FLAG_FILE");
    if (!flag_file) {
        flag_file = "/flag";
    }
    
    std::ifstream file(flag_file);
    if (file.is_open()) {
        std::string flag;
        std::getline(file, flag);
        file.close();
        
        if (!flag.empty()) {
            return flag;
        }
    }
    
    return "no flag configured! contact orga";
}

// Compare two decks to check if they are identical
bool compareDecks(const int* deck1, const int* deck2, int size) {
    for (int i = 0; i < size; i++) {
        if (deck1[i] != deck2[i]) {
            return false;
        }
    }
    return true;
}

// Read cards from user input
void readUserCards(int* deck, int size) {
    std::string card;
    for (int i = 0; i < size; i++) {
        std::cin >> card;
        deck[i] = convertCardToInt(card);
    }
}

// Main function for the card game
int main() {
    const int DECK_SIZE = 52;
    int cards[DECK_SIZE];
    int expected_cards[DECK_SIZE];
    
    // Initialize cards in order
    for (int i = 0; i < DECK_SIZE; i++) {
        cards[i] = i;
        expected_cards[i] = i;
    }
    
    // Get SEED environment variable or use 1337 as default
    const char* seed_env = std::getenv("SEED");
    std::string seed_str = seed_env ? seed_env : "1337";
    
    unsigned long long env_seed;
    try {
        env_seed = std::stoull(seed_str);
    } catch (...) {
        env_seed = 1337;
    }
    
    env_seed %= 0xFFFFFF;
    
    // Print warning message if default seed
    if (env_seed == 1337) {
        std::cout << "⚠️🚨⚠️ Using default seed, please set SEED env var to a different value ⚠️🚨⚠️" << std::endl;
    }
    
    std::cout << "holographic" << std::endl;
    
    // Print unshuffled deck at the start
    displayDeck(cards, DECK_SIZE);
    std::cout << std::endl;
    
    // Main game loop
    while (true) {
        if (std::cout.fail() || std::cin.fail()) {
            break;
        }
        
        // Create actual random seed using random_device
        std::random_device rd;
        unsigned int actual_seed = rd();
        
        // CORRECT: Setup vector for seed data with both seeds
        std::vector<uint32_t> seedData;
        seedData.push_back(actual_seed);  // Displayed seed
        seedData.push_back(env_seed);     // Environment seed
        
        // CORRECT: Initialize custom MT state with both seeds
        uint32_t mt_state[N];
        customMTMixing(seedData, mt_state, N);
        
        // CORRECT: Create custom MT instance and set its state
        CustomMT19937 rng(0); // Dummy seed, will be overwritten
        rng.setState(mt_state);
        
        // Reset and shuffle the expected cards using the properly seeded RNG
        for (int i = 0; i < DECK_SIZE; i++) {
            expected_cards[i] = i;
        }
        shuffleDeck(expected_cards, DECK_SIZE, rng);
        
        // Display the seed and prompt
        std::cout << "seed: " << std::hex << actual_seed << std::dec << std::endl;
        std::cout << "show me your cards" << std::endl;
        
        // Read user's cards
        readUserCards(cards, DECK_SIZE);
        
        // Compare and provide output
        if (compareDecks(expected_cards, cards, DECK_SIZE)) {
            std::cout << "Looks like you weren't bluffing!" << std::endl;
            std::cout << getFlag() << std::endl;
            break;
        } else {
            std::cout << "Oh no, were you bluffing too?" << std::endl;
            displayDeck(expected_cards, DECK_SIZE);
        }
    }
    
    return 0;
}