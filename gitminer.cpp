#include <cstdio>
#include <cstdint>
#include <cinttypes>
#include <cstring>
#include <cstdlib>

#include <chrono>
#include <iostream>
#include <fstream>
#include <string>
#include <random>
#include <thread>
#include <mutex>
#include <vector>
#include <atomic>

using namespace std;

//nonce range (characters to use)
#define range_lower 'a'
#define range_upper 'z' //inclusive

#define data_len_max 4096

//configurable parameters (set from CLI)
int g_nonce_start = 237;
int g_nonce_end = 246;
int g_target_zeros = 0; //0 = run forever

int logmode = 1;
string filename_log, filename_out;
atomic<bool> g_found(false);

uint32_t g_prefix[5] = {0};
uint32_t g_prefix_mask[5] = {0};
int g_prefix_mode = 0;
string g_target_prefix_str;

void parse_hex_prefix(const char *hex, uint32_t *prefix, uint32_t *mask) {
	memset(prefix, 0, 5 * sizeof(uint32_t));
	memset(mask, 0, 5 * sizeof(uint32_t));
	int len = strlen(hex);
	for (int i = 0; i < len && i < 40; i++) {
		int word = i / 8;
		int shift = (7 - (i % 8)) * 4;
		char c = hex[i];
		uint8_t val;
		if (c >= '0' && c <= '9') val = c - '0';
		else if (c >= 'a' && c <= 'f') val = c - 'a' + 10;
		else if (c >= 'A' && c <= 'F') val = c - 'A' + 10;
		else { fprintf(stderr, "Invalid hex character: %c\n", c); exit(1); }
		prefix[word] |= (uint32_t)val << shift;
		mask[word] |= (uint32_t)0xF << shift;
	}
}

inline bool matches_prefix(const uint32_t *hash, const uint32_t *prefix, const uint32_t *mask) {
	for (int i = 0; i < 5; i++)
		if ((hash[i] & mask[i]) != prefix[i]) return false;
	return true;
}

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (w[i] = (rol(w[i],24)&0xff00ff00)|(rol(w[i],8)&0x00ff00ff)) //little endian system
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) w[i]
#endif

#define blk(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
#define R0(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk0(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R1(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R2(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0x6ed9eba1+rol(l,5);m=rol(m,30);
#define R3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+blk(q)+0x8f1bbcdc+rol(l,5);m=rol(m,30);
#define R4(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0xca62c1d6+rol(l,5);m=rol(m,30);

void log_msg(string output);

inline void sha1_expand(uint8_t *data, int *data_len) {
	uint64_t m1;
	uint32_t seq;

	//message length
	m1 = (uint64_t) (*data_len) * 8;
	data[*data_len] = 0x80;

	seq = (*data_len)+1;
	*data_len = ((*data_len)+8)/64*64+56;
	//padding
	memset(data+seq, 0x00, (*data_len)-seq);

	//fill data as big endian converted m1
	data[(*data_len)] = (m1 >> 56) & 0xff; data[++(*data_len)] = (m1 >> 48) & 0xff;
	data[++(*data_len)] = (m1 >> 40) & 0xff; data[++(*data_len)] = (m1 >> 32) & 0xff;
	data[++(*data_len)] = (m1 >> 24) & 0xff; data[++(*data_len)] = (m1 >> 16) & 0xff;
	data[++(*data_len)] = (m1 >> 8) & 0xff; data[++(*data_len)] = (m1) & 0xff;

	++(*data_len);
}

inline void sha1_block(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e; //temp variables
	uint32_t w[16]; //words
	memcpy(w, (uint32_t*) data_block, 64);

	a = result[0];
	b = result[1];
	c = result[2];
	d = result[3];
	e = result[4];
	R0(a,b,c,d,e,0); R0(e,a,b,c,d,1); R0(d,e,a,b,c,2); R0(c,d,e,a,b,3);
	R0(b,c,d,e,a,4); R0(a,b,c,d,e,5); R0(e,a,b,c,d,6); R0(d,e,a,b,c,7);
	R0(c,d,e,a,b,8); R0(b,c,d,e,a,9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
	R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
	R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
	R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
	R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
	R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
	R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
	R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
	R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
	R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
	R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
	R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
	R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
	R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
	R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
	R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
	R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
	R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
	result[0] += a;
	result[1] += b;
	result[2] += c;
	result[3] += d;
	result[4] += e;
}

inline void sha1_init(uint32_t *result) {
	result[0] = 0x67452301;
	result[1] = 0xefcdab89;
	result[2] = 0x98badcfe;
	result[3] = 0x10325476;
	result[4] = 0xc3d2e1f0;
}

//check if hash has N leading hex zeros
inline bool has_leading_zeros(uint32_t *result, int target) {
	int full_words = target / 8;
	int remaining = target % 8;
	for (int i = 0; i < full_words && i < 5; ++i) {
		if (result[i] != 0) return false;
	}
	if (remaining > 0 && full_words < 5) {
		uint32_t mask = ~((1u << (32 - remaining * 4)) - 1);
		if (result[full_words] & mask) return false;
	}
	return true;
}

//lexicographic comparison: is a < b?
inline bool is_lower_hash(uint32_t *a, uint32_t *b) {
	for (int i = 0; i < 5; ++i) {
		if (a[i] < b[i]) return true;
		if (a[i] > b[i]) return false;
	}
	return false;
}

//thread worker function
void run_set_thread(uint8_t *data_input, uint8_t *nonce, int data_len, int nonce_len, int epoch_count,
	uint32_t *global_result_lowest, uint8_t *global_data_lowest, mutex &result_mutex) {

	int nonce_start = g_nonce_start;
	int nonce_size = g_nonce_end - g_nonce_start;
	int data_len_original = data_len;

	//variable to perform search
	int range_search;

	//local data copy for this thread
	uint8_t data[data_len_max];
	memcpy(data, data_input, data_len);
	memcpy(data + nonce_start, nonce, nonce_size);
	uint32_t result_cache[5];
	uint32_t result[5];

	//local best for this thread
	uint32_t local_best_result[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint8_t local_best_nonce[256];

	//pad the data
	sha1_expand(data, &data_len);

	//pre-compute: cache all SHA-1 blocks before the one containing the nonce
	int nonce_block_start = (nonce_start / 64) * 64;
	sha1_init(result_cache);
	for (int i = 0; i < nonce_block_start; i += 64) {
		sha1_block(data + i, result_cache);
	}

	for (int i = 0; i < epoch_count; ++i) {
		if (g_found.load(memory_order_relaxed)) break;

		//calculate the least significant nonce via for loop
		for (int j = range_lower; j < range_upper; ++j) {
			data[nonce_start] = j;
			memcpy(result, result_cache, 5 * 4);
			//compute all remaining blocks from nonce block onward
			for (int blk = nonce_block_start; blk < data_len; blk += 64) {
				sha1_block(data + blk, result);
			}

			if (g_prefix_mode) {
				if (matches_prefix(result, g_prefix, g_prefix_mask)) {
					memcpy(local_best_result, result, 5 * 4);
					memcpy(local_best_nonce, data + nonce_start, nonce_size);
					// Immediately report prefix match
					lock_guard<mutex> lock(result_mutex);
					memcpy(global_result_lowest, local_best_result, 5 * 4);
					memcpy(global_data_lowest + nonce_start, local_best_nonce, nonce_size);

					char buf2[1000], buf_nonce2[256];
					for (int j2 = 0; j2 < nonce_size; ++j2)
						buf_nonce2[j2] = global_data_lowest[nonce_start + j2];
					buf_nonce2[nonce_size] = 0;
					snprintf(buf2, sizeof(buf2), "Found prefix match: %08x%08x%08x%08x%08x (nonce: %s)",
						global_result_lowest[0], global_result_lowest[1], global_result_lowest[2],
						global_result_lowest[3], global_result_lowest[4], buf_nonce2);
					log_msg(buf2);

					ofstream file_out2;
					file_out2.open(filename_out, ios::out | ios::binary);
					file_out2.write((char*)global_data_lowest, data_len_original);
					file_out2.close();

					g_found.store(true, memory_order_relaxed);
					return;
				}
			} else {
				if (is_lower_hash(result, local_best_result)) {
					memcpy(local_best_result, result, 5 * 4);
					memcpy(local_best_nonce, data + nonce_start, nonce_size);
				}
			}
		}

		//calculate the next nonce
		range_search = nonce_start + 1;
		data[nonce_start + 1]++;
		while (data[range_search] > range_upper) {
			data[range_search] = range_lower;
			range_search++;
			data[range_search]++;
		}
	}

	//update nonce state for next batch
	memcpy(nonce, data + nonce_start, nonce_size);

	//update global best under lock
	if (is_lower_hash(local_best_result, global_result_lowest)) {
		lock_guard<mutex> lock(result_mutex);
		//re-check under lock
		if (is_lower_hash(local_best_result, global_result_lowest)) {
			memcpy(global_result_lowest, local_best_result, 5 * 4);
			memcpy(global_data_lowest + nonce_start, local_best_nonce, nonce_size);

			char buf[1000], buf_nonce[256];
			for (int j = 0; j < nonce_len; ++j) {
				buf_nonce[j] = global_data_lowest[nonce_start + j];
			}
			buf_nonce[nonce_len] = 0;
			snprintf(buf, sizeof(buf), "Found new lowest value: %08x%08x%08x%08x%08x (nonce: %s)",
				global_result_lowest[0], global_result_lowest[1], global_result_lowest[2],
				global_result_lowest[3], global_result_lowest[4], buf_nonce);
			log_msg(buf);

			//write result
			ofstream file_out;
			file_out.open(filename_out, ios::out | ios::binary);
			file_out.write((char*)global_data_lowest, data_len_original);
			file_out.close();

			//check if target met
			if (g_target_zeros > 0 && has_leading_zeros(local_best_result, g_target_zeros)) {
				g_found.store(true, memory_order_relaxed);
			}
		}
	}
}

//initialize nonce with random values
void init_nonce(uint8_t *nonce, int nonce_size) {
	int nonce_len_var = min(6, nonce_size);
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> dist(range_lower, range_upper);

	//random nonce for non-variable part
	for (int i = nonce_len_var; i < nonce_size; ++i) {
		nonce[i] = (uint8_t) dist(mt);
	}
	//variable part starts at range_lower
	for (int i = 0; i < nonce_len_var; ++i) {
		nonce[i] = (uint8_t) range_lower;
	}
}

void log_msg(string output) {
	ofstream file_log;
	file_log.open(filename_log, ios::out | ios::app);
	file_log << output << endl;
	if (logmode) {
		cout << output << endl;
	}
	file_log.close();
}

int main(int argc, char *argv[]) {
	uint8_t *DATA;
	uint32_t RESULT_LOWEST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint8_t *DATA_LOWEST;
	uint32_t DATA_LEN, PADDED_LEN;

	int NUM_THREADS = (int) thread::hardware_concurrency();
	if (NUM_THREADS <= 0) NUM_THREADS = 4;
	int EPOCH_COUNT = 100000;

	//parse CLI: threads logfile resultfile [nonce_start nonce_end target_zeros]
	if (argc > 1) {
		NUM_THREADS = atoi(argv[1]);
		if (NUM_THREADS <= 0) NUM_THREADS = 4;
	}

	if (argc > 2) {
		filename_log = argv[2];
		logmode = 0;
	} else {
		filename_log = "log.txt";
	}

	if (argc > 3) {
		filename_out = argv[3];
	} else {
		filename_out = "result.txt";
	}

	if (argc > 4) {
		g_nonce_start = atoi(argv[4]);
	}
	if (argc > 5) {
		g_nonce_end = atoi(argv[5]);
	}
	if (argc > 6) {
		g_target_zeros = atoi(argv[6]);
	}
	if (argc > 7) {
		g_target_prefix_str = argv[7];
		parse_hex_prefix(argv[7], g_prefix, g_prefix_mask);
		g_prefix_mode = 1;
	}

	log_msg("Reading data");

	//read file
	ifstream file_base;
	file_base.open("base.txt", ios::in | ios::binary | ios::ate);
	if (!file_base.is_open()) {
		log_msg("base.txt not exist.");
		return 1;
	}
	DATA_LEN = file_base.tellg();

	if (DATA_LEN >= data_len_max) {
		log_msg("Error: input data too large (max " + to_string(data_len_max) + " bytes)");
		return 1;
	}

	//calculate length after padding (to allocate memory)
	if (DATA_LEN % 64 <= 55) {
		PADDED_LEN = DATA_LEN / 64 * 64 + 64;
	} else {
		PADDED_LEN = DATA_LEN / 64 * 64 + 128;
	}

	DATA = (uint8_t*) calloc(PADDED_LEN, sizeof(uint8_t));
	DATA_LOWEST = (uint8_t*) calloc(PADDED_LEN, sizeof(uint8_t));

	file_base.seekg(0, ios::beg);
	file_base.read((char*)DATA, DATA_LEN);
	file_base.close();
	log_msg("Read " + to_string(DATA_LEN) + " bytes.");

	uint32_t NONCE_LEN = g_nonce_end - g_nonce_start;

	log_msg("Using " + to_string(NUM_THREADS) + " CPU threads");
	log_msg("Nonce region: [" + to_string(g_nonce_start) + ", " + to_string(g_nonce_end) + ") length=" + to_string(NONCE_LEN));
	if (g_prefix_mode) {
		log_msg("Target prefix: " + g_target_prefix_str);
	} else if (g_target_zeros > 0) {
		log_msg("Target: " + to_string(g_target_zeros) + " leading hex zeros");
	} else {
		log_msg("Target: run forever (find lowest hash)");
	}

	log_msg("Allocating memory...");

	//per-thread nonce storage
	vector<vector<uint8_t>> thread_nonces(NUM_THREADS, vector<uint8_t>(NONCE_LEN));

	log_msg("Initializing nonces");
	for (int i = 0; i < NUM_THREADS; ++i) {
		init_nonce(thread_nonces[i].data(), NONCE_LEN);
	}
	memcpy(DATA_LOWEST, DATA, DATA_LEN);

	mutex result_mutex;

	//time measurement
	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0;
	uint64_t processed_last = 0;

	auto end = chrono::high_resolution_clock::now();
	auto elapsed = begin - end, elapsed_last = begin - end, elapsed_log = begin - end;

	char buf[1000];

	log_msg("Launching CPU threads");

	for (;;) {
		vector<thread> threads;
		for (int i = 0; i < NUM_THREADS; ++i) {
			threads.emplace_back(run_set_thread,
				DATA, thread_nonces[i].data(),
				DATA_LEN, NONCE_LEN, EPOCH_COUNT,
				RESULT_LOWEST, DATA_LOWEST, ref(result_mutex));
		}

		for (auto &t : threads) {
			t.join();
		}

		if (g_found.load()) {
			log_msg("Target reached! Exiting.");
			break;
		}

		processed += (uint64_t) NUM_THREADS * EPOCH_COUNT * (range_upper - range_lower + 1);

		end = chrono::high_resolution_clock::now();
		elapsed_log = chrono::duration_cast<chrono::nanoseconds>(end - begin_log);
		if (1e9 * 10 < (double)elapsed_log.count()) {
			elapsed = chrono::duration_cast<chrono::nanoseconds>(end - begin);
			snprintf(buf, sizeof(buf), "Processed %" PRIu64 "G hashes (%.2fMH/s)\n", processed / 1000000000, (1e3 * (processed - processed_last) / (elapsed.count() - elapsed_last.count())));
			elapsed_last = elapsed;
			processed_last = processed;
			log_msg(buf);
			begin_log = chrono::high_resolution_clock::now();
		}
	}

	free(DATA);
	free(DATA_LOWEST);
	return 0;
}
