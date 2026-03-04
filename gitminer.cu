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

using namespace std;

#define range_lower 'a'
#define range_upper 'z'

int g_nonce_start = 237;
int g_nonce_end = 246;
int g_target_zeros = 0;
int logmode = 1;
string filename_log, filename_out;

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (w[i] = (rol(w[i],24)&0xff00ff00)|(rol(w[i],8)&0x00ff00ff))
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) w[i]
#endif

#define blk(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
#define R0(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk0(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R1(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R2(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0x6ed9eba1+rol(l,5);m=rol(m,30);
#define R3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+blk(q)+0x8f1bbcdc+rol(l,5);m=rol(m,30);
#define R4(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0xca62c1d6+rol(l,5);m=rol(m,30);

// ── Host-side SHA-1 (for pre-compute cache) ──

inline void sha1_expand_host(uint8_t *data, int *data_len) {
	uint64_t m1 = (uint64_t)(*data_len) * 8;
	data[*data_len] = 0x80;
	uint32_t seq = (*data_len) + 1;
	*data_len = ((*data_len) + 8) / 64 * 64 + 56;
	memset(data + seq, 0x00, (*data_len) - seq);
	data[(*data_len)] = (m1 >> 56) & 0xff; data[++(*data_len)] = (m1 >> 48) & 0xff;
	data[++(*data_len)] = (m1 >> 40) & 0xff; data[++(*data_len)] = (m1 >> 32) & 0xff;
	data[++(*data_len)] = (m1 >> 24) & 0xff; data[++(*data_len)] = (m1 >> 16) & 0xff;
	data[++(*data_len)] = (m1 >> 8) & 0xff; data[++(*data_len)] = (m1) & 0xff;
	++(*data_len);
}

inline void sha1_block_host(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e;
	uint32_t w[16];
	memcpy(w, data_block, 64);
	a = result[0]; b = result[1]; c = result[2]; d = result[3]; e = result[4];
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
	result[0] += a; result[1] += b; result[2] += c; result[3] += d; result[4] += e;
}

inline void sha1_init_host(uint32_t *result) {
	result[0] = 0x67452301; result[1] = 0xefcdab89;
	result[2] = 0x98badcfe; result[3] = 0x10325476; result[4] = 0xc3d2e1f0;
}

// ── Device-side SHA-1 ──

__device__ inline void dev_memcpy(uint8_t *dst, const uint8_t *src, int num) {
	for (int i = 0; i < num; ++i) dst[i] = src[i];
}

__device__ inline void dev_sha1_block(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e;
	uint32_t w[16];
	// Load as bytes to avoid alignment issues
	for (int i = 0; i < 16; i++) {
		int idx = i * 4;
		w[i] = ((uint32_t)data_block[idx]) | ((uint32_t)data_block[idx+1] << 8)
			 | ((uint32_t)data_block[idx+2] << 16) | ((uint32_t)data_block[idx+3] << 24);
	}
	// blk0 byte-swaps for little endian
	a = result[0]; b = result[1]; c = result[2]; d = result[3]; e = result[4];
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
	result[0] += a; result[1] += b; result[2] += c; result[3] += d; result[4] += e;
}

__device__ inline bool dev_is_lower(uint32_t *a, uint32_t *b) {
	for (int i = 0; i < 5; ++i) {
		if (a[i] < b[i]) return true;
		if (a[i] > b[i]) return false;
	}
	return false;
}

// ── Kernel: minimal per-thread memory, host pre-computes state ──

__global__ void run_set(
	const uint8_t *data_padded,   // Full padded data (read-only, L2-cached)
	const uint32_t *state_cache,  // Pre-computed SHA-1 state for blocks before nonce (5 uint32)
	uint8_t *nonces,              // Per-thread nonces (read/write)
	uint8_t *best_nonces,         // Per-thread best nonces found
	uint32_t *best_results,       // Per-thread best hash results (5 uint32 each)
	int padded_len,
	int nonce_size,
	int epoch_count,
	int nonce_start,
	int nonce_block_start)
{
	int tid = blockIdx.x * blockDim.x + threadIdx.x;
	int nonce_offset = nonce_start - nonce_block_start;

	// Load nonce block template (64 bytes) — only block containing nonce
	uint8_t nonce_block[64];
	dev_memcpy(nonce_block, data_padded + nonce_block_start, 64);

	// Load per-thread nonce into nonce_block
	uint8_t my_nonce[32];
	for (int i = 0; i < nonce_size; i++) {
		my_nonce[i] = nonces[tid * nonce_size + i];
		nonce_block[nonce_offset + i] = my_nonce[i];
	}

	// Temp block for reading remaining blocks from global memory
	uint8_t temp_block[64];

	for (int ep = 0; ep < epoch_count; ep++) {
		for (int j = range_lower; j <= range_upper; j++) {
			nonce_block[nonce_offset] = (uint8_t)j;

			// Restore cached state
			uint32_t result[5];
			result[0] = state_cache[0]; result[1] = state_cache[1];
			result[2] = state_cache[2]; result[3] = state_cache[3];
			result[4] = state_cache[4];

			// Process nonce block
			dev_sha1_block(nonce_block, result);

			// Process remaining blocks from global memory (L2 cached)
			for (int blk_off = nonce_block_start + 64; blk_off < padded_len; blk_off += 64) {
				dev_memcpy(temp_block, data_padded + blk_off, 64);
				dev_sha1_block(temp_block, result);
			}

			// Check if lower than thread-local best
			if (dev_is_lower(result, best_results + tid * 5)) {
				best_nonces[tid * nonce_size] = (uint8_t)j;
				for (int i = 1; i < nonce_size; i++)
					best_nonces[tid * nonce_size + i] = my_nonce[i];
				for (int i = 0; i < 5; i++)
					best_results[tid * 5 + i] = result[i];
			}
		}

		// Advance nonce (positions 1+)
		my_nonce[1]++;
		int rs = 1;
		while (my_nonce[rs] > range_upper) {
			my_nonce[rs] = range_lower;
			rs++;
			if (rs >= nonce_size) break;
			my_nonce[rs]++;
		}
		for (int i = 1; i < nonce_size; i++)
			nonce_block[nonce_offset + i] = my_nonce[i];
	}

	// Write back nonces
	for (int i = 0; i < nonce_size; i++)
		nonces[tid * nonce_size + i] = nonce_block[nonce_offset + i];
}

// ── Host utilities ──

void init_nonce(uint8_t *nonce, int nonce_size) {
	int nonce_len_var = min(6, nonce_size);
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> dist(range_lower, range_upper);
	for (int i = nonce_len_var; i < nonce_size; ++i)
		nonce[i] = (uint8_t)dist(mt);
	for (int i = 0; i < nonce_len_var; ++i)
		nonce[i] = (uint8_t)range_lower;
}

void log_msg(string output) {
	ofstream file_log;
	file_log.open(filename_log, ios::out | ios::app);
	file_log << output << endl;
	if (logmode) cout << output << endl;
	file_log.close();
}

inline bool has_leading_zeros(uint32_t *result, int target) {
	int full_words = target / 8;
	int remaining = target % 8;
	for (int i = 0; i < full_words && i < 5; ++i)
		if (result[i] != 0) return false;
	if (remaining > 0 && full_words < 5) {
		uint32_t mask = ~((1u << (32 - remaining * 4)) - 1);
		if (result[full_words] & mask) return false;
	}
	return true;
}

inline bool is_lower_hash_host(uint32_t *a, uint32_t *b) {
	for (int i = 0; i < 5; ++i) {
		if (a[i] < b[i]) return true;
		if (a[i] > b[i]) return false;
	}
	return false;
}

int main(int argc, char *argv[]) {
	uint32_t RESULT_LOWEST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint32_t DATA_LEN;

	char buf[1000], buf_nonce[256];

	// RTX 4090: 128 SMs, maximize occupancy
	int NUM_BLOCKS = 1024;
	int NUM_THREADS = 256;
	int EPOCH_COUNT = 1000;

	if (argc > 1) { cudaSetDevice(atoi(argv[1])); }
	if (argc > 2) { filename_log = argv[2]; logmode = 0; } else { filename_log = "log.txt"; }
	if (argc > 3) { filename_out = argv[3]; } else { filename_out = "result.txt"; }
	if (argc > 4) { g_nonce_start = atoi(argv[4]); }
	if (argc > 5) { g_nonce_end = atoi(argv[5]); }
	if (argc > 6) { g_target_zeros = atoi(argv[6]); }

	log_msg("Reading data");

	ifstream file_base;
	file_base.open("base.txt", ios::in | ios::binary | ios::ate);
	if (!file_base.is_open()) { log_msg("base.txt not found."); return 1; }
	DATA_LEN = file_base.tellg();

	uint32_t PADDED_LEN;
	if (DATA_LEN % 64 <= 55) PADDED_LEN = DATA_LEN / 64 * 64 + 64;
	else PADDED_LEN = DATA_LEN / 64 * 64 + 128;

	vector<uint8_t> DATA(PADDED_LEN, 0);
	vector<uint8_t> DATA_LOWEST(PADDED_LEN, 0);
	file_base.seekg(0, ios::beg);
	file_base.read((char*)DATA.data(), DATA_LEN);
	file_base.close();
	log_msg("Read " + to_string(DATA_LEN) + " bytes.");
	memcpy(DATA_LOWEST.data(), DATA.data(), DATA_LEN);

	int device_count;
	cudaGetDeviceCount(&device_count);
	log_msg(to_string(device_count) + " CUDA device(s) found");

	uint32_t NONCE_LEN = g_nonce_end - g_nonce_start;
	int nonce_block_start = (g_nonce_start / 64) * 64;

	// Pad data on host
	int padded_len_int = (int)DATA_LEN;
	sha1_expand_host(DATA.data(), &padded_len_int);
	PADDED_LEN = (uint32_t)padded_len_int;

	// Pre-compute SHA-1 state for blocks before nonce block
	uint32_t state_cache[5];
	sha1_init_host(state_cache);
	for (int i = 0; i < nonce_block_start; i += 64)
		sha1_block_host(DATA.data() + i, state_cache);

	log_msg("Pre-computed SHA-1 cache for " + to_string(nonce_block_start / 64) + " blocks");
	log_msg("Remaining blocks per hash: " + to_string((PADDED_LEN - nonce_block_start) / 64));
	log_msg("Nonce region: [" + to_string(g_nonce_start) + ", " + to_string(g_nonce_end) + ")");
	log_msg("Grid: " + to_string(NUM_BLOCKS) + " blocks x " + to_string(NUM_THREADS) +
		" threads = " + to_string(NUM_BLOCKS * NUM_THREADS) + " total");
	if (g_target_zeros > 0)
		log_msg("Target: " + to_string(g_target_zeros) + " leading hex zeros");

	// Allocate device memory
	uint64_t total_threads = (uint64_t)NUM_BLOCKS * NUM_THREADS;

	uint8_t *d_data, *d_nonces, *d_best_nonces;
	uint32_t *d_state_cache, *d_best_results;

	cudaMalloc(&d_data, PADDED_LEN);
	cudaMalloc(&d_state_cache, 5 * sizeof(uint32_t));
	cudaMalloc(&d_nonces, total_threads * NONCE_LEN);
	cudaMalloc(&d_best_nonces, total_threads * NONCE_LEN);
	cudaMalloc(&d_best_results, total_threads * 5 * sizeof(uint32_t));

	// Host buffers
	uint8_t *h_nonces = (uint8_t*)malloc(total_threads * NONCE_LEN);
	uint32_t *h_best_results = (uint32_t*)malloc(total_threads * 5 * sizeof(uint32_t));
	uint8_t *h_best_nonces = (uint8_t*)malloc(total_threads * NONCE_LEN);

	// Initialize nonces
	for (uint64_t i = 0; i < total_threads; i++)
		init_nonce(h_nonces + i * NONCE_LEN, NONCE_LEN);
	memset(h_best_results, 0xff, total_threads * 5 * sizeof(uint32_t));

	// Copy to device
	cudaMemcpy(d_data, DATA.data(), PADDED_LEN, cudaMemcpyHostToDevice);
	cudaMemcpy(d_state_cache, state_cache, 5 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	cudaMemcpy(d_nonces, h_nonces, total_threads * NONCE_LEN, cudaMemcpyHostToDevice);
	cudaMemcpy(d_best_results, h_best_results, total_threads * 5 * sizeof(uint32_t), cudaMemcpyHostToDevice);
	cudaDeviceSynchronize();

	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0, processed_last = 0;
	bool found = false;

	log_msg("Launching CUDA kernels");

	for (;;) {
		run_set<<<NUM_BLOCKS, NUM_THREADS>>>(
			d_data, d_state_cache, d_nonces, d_best_nonces, d_best_results,
			PADDED_LEN, NONCE_LEN, EPOCH_COUNT, g_nonce_start, nonce_block_start);
		cudaDeviceSynchronize();

		processed += (uint64_t)total_threads * EPOCH_COUNT * (range_upper - range_lower + 1);

		// Read back results
		cudaMemcpy(h_best_results, d_best_results, total_threads * 5 * sizeof(uint32_t), cudaMemcpyDeviceToHost);
		cudaMemcpy(h_best_nonces, d_best_nonces, total_threads * NONCE_LEN, cudaMemcpyDeviceToHost);

		for (uint64_t i = 0; i < total_threads; ++i) {
			if (is_lower_hash_host(h_best_results + 5 * i, RESULT_LOWEST)) {
				memcpy(RESULT_LOWEST, h_best_results + 5 * i, 5 * 4);
				memcpy(DATA_LOWEST.data() + g_nonce_start, h_best_nonces + i * NONCE_LEN, NONCE_LEN);

				for (uint32_t j = 0; j < NONCE_LEN; j++)
					buf_nonce[j] = DATA_LOWEST[g_nonce_start + j];
				buf_nonce[NONCE_LEN] = 0;
				snprintf(buf, sizeof(buf),
					"Found new lowest value: %08x%08x%08x%08x%08x (nonce: %s)",
					RESULT_LOWEST[0], RESULT_LOWEST[1], RESULT_LOWEST[2],
					RESULT_LOWEST[3], RESULT_LOWEST[4], buf_nonce);
				log_msg(buf);

				ofstream file_out;
				file_out.open(filename_out, ios::out | ios::binary);
				file_out.write((char*)DATA_LOWEST.data(), DATA_LEN);
				file_out.close();

				if (g_target_zeros > 0 && has_leading_zeros(RESULT_LOWEST, g_target_zeros))
					found = true;
			}
		}

		if (found) {
			log_msg("Target reached! Exiting.");
			break;
		}

		auto end = chrono::high_resolution_clock::now();
		double elapsed_log_s = chrono::duration<double>(end - begin_log).count();
		if (elapsed_log_s >= 5.0) {
			double rate = (double)(processed - processed_last) / elapsed_log_s;
			snprintf(buf, sizeof(buf), "Processed %" PRIu64 "G hashes (%.2fMH/s)",
				processed / 1000000000, rate / 1e6);
			processed_last = processed;
			log_msg(buf);
			begin_log = chrono::high_resolution_clock::now();
		}
	}

	cudaFree(d_data);
	cudaFree(d_state_cache);
	cudaFree(d_nonces);
	cudaFree(d_best_nonces);
	cudaFree(d_best_results);
	free(h_nonces);
	free(h_best_results);
	free(h_best_nonces);

	return 0;
}
