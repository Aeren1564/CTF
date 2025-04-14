// #include <bits/allocator.h> // Temp fix for gcc13 global pragma
// #pragma GCC target("avx2,bmi2,popcnt,lzcnt")
// #pragma GCC optimize("O3,unroll-loops")
#include <bits/stdc++.h>
// #include <x86intrin.h>
using namespace std;
#if __cplusplus >= 202002L
using namespace numbers;
#endif

auto shuffle(unsigned int state, unsigned int m){
	array<int, 52> res;
	ranges::iota(res, 0);
	// m ^= 0x77777777;
	constexpr unsigned int c = 0x000007e5;
	constexpr unsigned int mod = 0x7fffffff;
	for(auto i = 51; i >= 0; -- i){
		state = (state * m + c & 0xffffffff) % mod;
		int j = state % (i + 1);
		swap(res[i], res[j]);
	}
	return res;
}

atomic<int> found_m = -1;
vector<pair<int, array<int, 52>>> outputs;
void check(int rem, int stride){
	for(auto m = rem; m < 0x7fffffff && !~found_m; m += stride){
		for(auto [state, output]: outputs){
			if(shuffle(state, m) != output){
				goto FAIL;
			}
		}
		cout << "Found!, " << m << endl;
		found_m = m;
		break;
		FAIL:;
	}
}

int main(){
	ifstream fin("output.txt");
	while(true){
		string cur;
		if(!getline(fin, cur)){
			break;
		}
		istringstream iss(cur);
		int seed;
		iss >> seed;
		array<int, 52> deck;
		for(auto i = 0; i < 52; ++ i){
			iss >> deck[i];
		}
		outputs.push_back({seed, deck});
	}
	int num_threads = thread::hardware_concurrency();
	cout << "num_threads = " << num_threads << endl;
	vector<thread> threads;
	for (auto i = 0; i < num_threads; ++ i){
		threads.emplace_back(check, i, num_threads);
	}
	for(auto &t: threads){
		t.join();
	}
	ofstream fout("m.txt");
	fout << found_m << "\n";
	return 0;
}

/*

*/