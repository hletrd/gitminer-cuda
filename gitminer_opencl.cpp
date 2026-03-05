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
#include <vector>

#ifdef __APPLE__
#include <OpenCL/opencl.h>
#else
#include <CL/cl.h>
#endif

using namespace std;

#define range_lower 'a'
#define range_upper 'z'

int g_nonce_start = 237;
int g_nonce_end = 246;
int g_target_zeros = 0;
int logmode = 1;
string filename_log, filename_out;

string g_target_prefix_str;
uint32_t g_prefix[5] = {0};
uint32_t g_prefix_mask[5] = {0};
int g_prefix_mode = 0;

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

// ── Host-side SHA-1 (for pre-compute cache) ──────────────────────────

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

inline void sha1_expand(uint8_t *data, int *data_len) {
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

inline void sha1_block(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e;
	uint32_t w[16];
	memcpy(w, (uint32_t*)data_block, 64);
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

inline void sha1_init(uint32_t *result) {
	result[0] = 0x67452301; result[1] = 0xefcdab89;
	result[2] = 0x98badcfe; result[3] = 0x10325476; result[4] = 0xc3d2e1f0;
}

// ── Utility functions ────────────────────────────────────────────────

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

inline bool is_lower_hash(uint32_t *a, uint32_t *b) {
	for (int i = 0; i < 5; ++i) {
		if (a[i] < b[i]) return true;
		if (a[i] > b[i]) return false;
	}
	return false;
}

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

// ── OpenCL Kernel Source ─────────────────────────────────────────────

static const char *openclKernelSource = R"(
#define RANGE_LOWER 97
#define RANGE_UPPER 122

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

void sha1_block_impl(__private uchar *data_block, __private uint *result) {
	uint a, b, c, d, e;
	uint w[16];
	for (int i = 0; i < 16; i++) {
		uint idx = i * 4;
		w[i] = ((uint)data_block[idx]) | ((uint)data_block[idx+1] << 8)
			 | ((uint)data_block[idx+2] << 16) | ((uint)data_block[idx+3] << 24);
	}

	// blk0: little-endian byte swap
	for (int i = 0; i < 16; i++)
		w[i] = (rol(w[i],24)&0xff00ff00u)|(rol(w[i],8)&0x00ff00ffu);

	a = result[0]; b = result[1]; c = result[2]; d = result[3]; e = result[4];

	// Rounds 0-15 (use w directly, already swapped)
	#define F0(l,m,n,o,p,q) p+=((m&(n^o))^o)+w[q]+0x5a827999u+rol(l,5);m=rol(m,30);
	F0(a,b,c,d,e,0);  F0(e,a,b,c,d,1);  F0(d,e,a,b,c,2);  F0(c,d,e,a,b,3);
	F0(b,c,d,e,a,4);  F0(a,b,c,d,e,5);  F0(e,a,b,c,d,6);  F0(d,e,a,b,c,7);
	F0(c,d,e,a,b,8);  F0(b,c,d,e,a,9);  F0(a,b,c,d,e,10); F0(e,a,b,c,d,11);
	F0(d,e,a,b,c,12); F0(c,d,e,a,b,13); F0(b,c,d,e,a,14); F0(a,b,c,d,e,15);

	// blk expansion + rounds 16-79
	#define BLK(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
	#define G1(l,m,n,o,p,q) p+=((m&(n^o))^o)+BLK(q)+0x5a827999u+rol(l,5);m=rol(m,30);
	#define G2(l,m,n,o,p,q) p+=(m^n^o)+BLK(q)+0x6ed9eba1u+rol(l,5);m=rol(m,30);
	#define G3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+BLK(q)+0x8f1bbcdcu+rol(l,5);m=rol(m,30);
	#define G4(l,m,n,o,p,q) p+=(m^n^o)+BLK(q)+0xca62c1d6u+rol(l,5);m=rol(m,30);

	G1(e,a,b,c,d,16); G1(d,e,a,b,c,17); G1(c,d,e,a,b,18); G1(b,c,d,e,a,19);
	G2(a,b,c,d,e,20); G2(e,a,b,c,d,21); G2(d,e,a,b,c,22); G2(c,d,e,a,b,23);
	G2(b,c,d,e,a,24); G2(a,b,c,d,e,25); G2(e,a,b,c,d,26); G2(d,e,a,b,c,27);
	G2(c,d,e,a,b,28); G2(b,c,d,e,a,29); G2(a,b,c,d,e,30); G2(e,a,b,c,d,31);
	G2(d,e,a,b,c,32); G2(c,d,e,a,b,33); G2(b,c,d,e,a,34); G2(a,b,c,d,e,35);
	G2(e,a,b,c,d,36); G2(d,e,a,b,c,37); G2(c,d,e,a,b,38); G2(b,c,d,e,a,39);
	G3(a,b,c,d,e,40); G3(e,a,b,c,d,41); G3(d,e,a,b,c,42); G3(c,d,e,a,b,43);
	G3(b,c,d,e,a,44); G3(a,b,c,d,e,45); G3(e,a,b,c,d,46); G3(d,e,a,b,c,47);
	G3(c,d,e,a,b,48); G3(b,c,d,e,a,49); G3(a,b,c,d,e,50); G3(e,a,b,c,d,51);
	G3(d,e,a,b,c,52); G3(c,d,e,a,b,53); G3(b,c,d,e,a,54); G3(a,b,c,d,e,55);
	G3(e,a,b,c,d,56); G3(d,e,a,b,c,57); G3(c,d,e,a,b,58); G3(b,c,d,e,a,59);
	G4(a,b,c,d,e,60); G4(e,a,b,c,d,61); G4(d,e,a,b,c,62); G4(c,d,e,a,b,63);
	G4(b,c,d,e,a,64); G4(a,b,c,d,e,65); G4(e,a,b,c,d,66); G4(d,e,a,b,c,67);
	G4(c,d,e,a,b,68); G4(b,c,d,e,a,69); G4(a,b,c,d,e,70); G4(e,a,b,c,d,71);
	G4(d,e,a,b,c,72); G4(c,d,e,a,b,73); G4(b,c,d,e,a,74); G4(a,b,c,d,e,75);
	G4(e,a,b,c,d,76); G4(d,e,a,b,c,77); G4(c,d,e,a,b,78); G4(b,c,d,e,a,79);

	result[0] += a; result[1] += b; result[2] += c; result[3] += d; result[4] += e;
}

typedef struct {
	uint nonce_start;
	uint nonce_end;
	uint epoch_count;
	uint nonce_block_start;
	uint padded_len;
	uint nonce_size;
	uint prefix_mode;
	uint prefix[5];
	uint prefix_mask[5];
} MineParams;

__kernel void mine_sha1(
	__global const uchar *data_padded,
	__constant uint *state_cache,
	__global uchar *nonces,
	__global uint *best_results,
	__global uchar *best_nonces,
	__constant MineParams *params,
	__global volatile int *found_flag
) {
	uint tid = get_global_id(0);

	uint nonce_start = params->nonce_start;
	uint nonce_size = params->nonce_size;
	uint epoch_count = params->epoch_count;
	uint nonce_block_start = params->nonce_block_start;
	uint padded_len = params->padded_len;
	uint nonce_offset = nonce_start - nonce_block_start;
	uint prefix_mode = params->prefix_mode;

	// Load prefix data into private memory
	uint pfx[5], pfx_mask[5];
	if (prefix_mode) {
		for (int i = 0; i < 5; i++) {
			pfx[i] = params->prefix[i];
			pfx_mask[i] = params->prefix_mask[i];
		}
	}

	// Load per-thread nonce
	uchar my_nonce[32];
	for (uint i = 0; i < nonce_size; i++)
		my_nonce[i] = nonces[tid * nonce_size + i];

	// Load nonce block template (64 bytes)
	uchar nonce_block[64];
	for (int i = 0; i < 64; i++)
		nonce_block[i] = data_padded[nonce_block_start + i];
	// Overlay nonce
	for (uint i = 0; i < nonce_size; i++)
		nonce_block[nonce_offset + i] = my_nonce[i];

	// Local best
	uint local_best[5];
	for (int i = 0; i < 5; i++) local_best[i] = best_results[tid * 5 + i];
	uchar local_best_nonce[32];
	for (uint i = 0; i < nonce_size; i++) local_best_nonce[i] = my_nonce[i];

	uchar temp_block[64];

	for (uint ep = 0; ep < epoch_count; ep++) {
		if (prefix_mode && *found_flag) break;

		for (int j = RANGE_LOWER; j <= RANGE_UPPER; j++) {
			nonce_block[nonce_offset] = (uchar)j;

			// Restore cached state
			uint result[5];
			for (int k = 0; k < 5; k++) result[k] = state_cache[k];

			// Process nonce block
			sha1_block_impl(nonce_block, result);

			// Process remaining blocks from global memory
			for (uint blk = nonce_block_start + 64; blk < padded_len; blk += 64) {
				for (int i = 0; i < 64; i++) temp_block[i] = data_padded[blk + i];
				sha1_block_impl(temp_block, result);
			}

			if (prefix_mode) {
				// Check prefix match
				bool match = true;
				for (int k = 0; k < 5; k++) {
					if ((result[k] & pfx_mask[k]) != pfx[k]) {
						match = false;
						break;
					}
				}
				if (match) {
					for (int k = 0; k < 5; k++) local_best[k] = result[k];
					local_best_nonce[0] = (uchar)j;
					for (uint i = 1; i < nonce_size; i++) local_best_nonce[i] = my_nonce[i];
					atomic_cmpxchg((__global volatile int *)found_flag, 0, 1);
				}
			} else {
				// Check if lower
				bool lower = false;
				for (int k = 0; k < 5; k++) {
					if (result[k] < local_best[k]) { lower = true; break; }
					if (result[k] > local_best[k]) { break; }
				}
				if (lower) {
					for (int k = 0; k < 5; k++) local_best[k] = result[k];
					local_best_nonce[0] = (uchar)j;
					for (uint i = 1; i < nonce_size; i++) local_best_nonce[i] = my_nonce[i];
				}
			}
		}

		// Advance nonce
		my_nonce[1]++;
		uint rs = 1;
		while (my_nonce[rs] > RANGE_UPPER) {
			my_nonce[rs] = RANGE_LOWER;
			rs++;
			my_nonce[rs]++;
		}
		for (uint i = 1; i < nonce_size; i++)
			nonce_block[nonce_offset + i] = my_nonce[i];
	}

	// Write back
	for (int i = 0; i < 5; i++) best_results[tid * 5 + i] = local_best[i];
	for (uint i = 0; i < nonce_size; i++) {
		nonces[tid * nonce_size + i] = my_nonce[i];
		best_nonces[tid * nonce_size + i] = local_best_nonce[i];
	}
}
)";

// ── OpenCL helpers ───────────────────────────────────────────────────

#define CL_CHECK(call) do { \
	cl_int err_ = (call); \
	if (err_ != CL_SUCCESS) { \
		fprintf(stderr, "OpenCL error %d at %s:%d\n", err_, __FILE__, __LINE__); \
		exit(1); \
	} \
} while(0)

static const char* cl_error_string(cl_int err) {
	switch (err) {
		case CL_SUCCESS: return "CL_SUCCESS";
		case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
		case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
		case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
		case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
		case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
		case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
		default: return "UNKNOWN";
	}
}

// ── Main ─────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
	uint32_t RESULT_LOWEST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint32_t DATA_LEN;

	int NUM_THREADS = 65536;
	int EPOCH_COUNT = 100;

	int device_id = 0;
	if (argc > 1) { device_id = atoi(argv[1]); }
	if (argc > 2) { filename_log = argv[2]; logmode = 0; } else { filename_log = "log.txt"; }
	if (argc > 3) { filename_out = argv[3]; } else { filename_out = "result.txt"; }
	if (argc > 4) { g_nonce_start = atoi(argv[4]); }
	if (argc > 5) { g_nonce_end = atoi(argv[5]); }
	if (argc > 6) { g_target_zeros = atoi(argv[6]); }
	if (argc > 7) {
		g_target_prefix_str = argv[7];
		parse_hex_prefix(argv[7], g_prefix, g_prefix_mask);
		g_prefix_mode = 1;
	}

	// Read base.txt
	log_msg("Reading data");
	ifstream file_base;
	file_base.open("base.txt", ios::in | ios::binary | ios::ate);
	if (!file_base.is_open()) { log_msg("base.txt not exist."); return 1; }
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

	uint32_t NONCE_LEN = g_nonce_end - g_nonce_start;
	int nonce_block_start = (g_nonce_start / 64) * 64;

	// Pad data on host
	int padded_len_int = (int)DATA_LEN;
	sha1_expand(DATA.data(), &padded_len_int);
	PADDED_LEN = (uint32_t)padded_len_int;

	// Pre-compute SHA-1 state for blocks before nonce block
	uint32_t state_cache[5];
	sha1_init(state_cache);
	for (int i = 0; i < nonce_block_start; i += 64)
		sha1_block(DATA.data() + i, state_cache);

	log_msg("Pre-computed SHA-1 cache for " + to_string(nonce_block_start / 64) + " blocks");
	log_msg("Remaining blocks per hash: " + to_string((PADDED_LEN - nonce_block_start) / 64));

	// ── OpenCL setup ──
	cl_int err;

	// Get platforms
	cl_uint num_platforms;
	CL_CHECK(clGetPlatformIDs(0, NULL, &num_platforms));
	if (num_platforms == 0) { log_msg("No OpenCL platforms found."); return 1; }

	vector<cl_platform_id> platforms(num_platforms);
	CL_CHECK(clGetPlatformIDs(num_platforms, platforms.data(), NULL));

	// Collect all GPU devices across all platforms
	vector<cl_device_id> all_devices;
	vector<cl_platform_id> device_platforms; // track which platform each device belongs to
	for (cl_uint p = 0; p < num_platforms; p++) {
		cl_uint num_devices;
		err = clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, 0, NULL, &num_devices);
		if (err != CL_SUCCESS || num_devices == 0) continue;
		vector<cl_device_id> devices(num_devices);
		CL_CHECK(clGetDeviceIDs(platforms[p], CL_DEVICE_TYPE_GPU, num_devices, devices.data(), NULL));
		for (cl_uint d = 0; d < num_devices; d++) {
			all_devices.push_back(devices[d]);
			device_platforms.push_back(platforms[p]);
		}
	}

	if (all_devices.empty()) { log_msg("No OpenCL GPU devices found."); return 1; }
	if (device_id >= (int)all_devices.size()) {
		log_msg("Device ID " + to_string(device_id) + " out of range (found " +
			to_string(all_devices.size()) + " devices).");
		return 1;
	}

	cl_device_id device = all_devices[device_id];
	cl_platform_id platform = device_platforms[device_id];

	char device_name[256];
	clGetDeviceInfo(device, CL_DEVICE_NAME, sizeof(device_name), device_name, NULL);
	log_msg("OpenCL device: " + string(device_name));

	// Create context and command queue
	cl_context context = clCreateContext(NULL, 1, &device, NULL, NULL, &err);
	if (err != CL_SUCCESS) { log_msg("Failed to create context: " + string(cl_error_string(err))); return 1; }

	// Use clCreateCommandQueue for OpenCL 1.2 compatibility
	cl_command_queue queue = clCreateCommandQueue(context, device, 0, &err);
	if (err != CL_SUCCESS) { log_msg("Failed to create command queue: " + string(cl_error_string(err))); return 1; }

	// Build program
	size_t src_len = strlen(openclKernelSource);
	cl_program program = clCreateProgramWithSource(context, 1, &openclKernelSource, &src_len, &err);
	if (err != CL_SUCCESS) { log_msg("Failed to create program: " + string(cl_error_string(err))); return 1; }

	err = clBuildProgram(program, 1, &device, "-cl-fast-relaxed-math", NULL, NULL);
	if (err != CL_SUCCESS) {
		size_t log_size;
		clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
		vector<char> build_log(log_size);
		clGetProgramBuildInfo(program, device, CL_PROGRAM_BUILD_LOG, log_size, build_log.data(), NULL);
		log_msg("Build error: " + string(build_log.data()));
		return 1;
	}

	cl_kernel kernel = clCreateKernel(program, "mine_sha1", &err);
	if (err != CL_SUCCESS) { log_msg("Failed to create kernel: " + string(cl_error_string(err))); return 1; }

	size_t workgroup_size;
	clGetKernelWorkGroupInfo(kernel, device, CL_KERNEL_WORK_GROUP_SIZE, sizeof(workgroup_size), &workgroup_size, NULL);
	if (workgroup_size > 256) workgroup_size = 256;

	log_msg("Using " + to_string(NUM_THREADS) + " GPU work items (" +
		to_string(workgroup_size) + " per work group)");
	log_msg("Nonce region: [" + to_string(g_nonce_start) + ", " + to_string(g_nonce_end) + ")");
	if (g_prefix_mode)
		log_msg("Target prefix: " + g_target_prefix_str);
	else if (g_target_zeros > 0)
		log_msg("Target: " + to_string(g_target_zeros) + " leading hex zeros");

	// Create buffers
	cl_mem dataBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		PADDED_LEN, DATA.data(), &err);
	CL_CHECK(err);

	cl_mem stateBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		sizeof(state_cache), state_cache, &err);
	CL_CHECK(err);

	cl_mem nonceBuf = clCreateBuffer(context, CL_MEM_READ_WRITE,
		NUM_THREADS * NONCE_LEN, NULL, &err);
	CL_CHECK(err);

	cl_mem resultBuf = clCreateBuffer(context, CL_MEM_READ_WRITE,
		NUM_THREADS * 5 * sizeof(uint32_t), NULL, &err);
	CL_CHECK(err);

	cl_mem bestNonceBuf = clCreateBuffer(context, CL_MEM_READ_WRITE,
		NUM_THREADS * NONCE_LEN, NULL, &err);
	CL_CHECK(err);

	// Params struct (must match kernel layout)
	struct {
		uint32_t nonce_start;
		uint32_t nonce_end;
		uint32_t epoch_count;
		uint32_t nonce_block_start;
		uint32_t padded_len;
		uint32_t nonce_size;
		uint32_t prefix_mode;
		uint32_t prefix[5];
		uint32_t prefix_mask[5];
	} params;
	params.nonce_start = (uint32_t)g_nonce_start;
	params.nonce_end = (uint32_t)g_nonce_end;
	params.epoch_count = (uint32_t)EPOCH_COUNT;
	params.nonce_block_start = (uint32_t)nonce_block_start;
	params.padded_len = PADDED_LEN;
	params.nonce_size = NONCE_LEN;
	params.prefix_mode = (uint32_t)g_prefix_mode;
	memcpy(params.prefix, g_prefix, 5 * sizeof(uint32_t));
	memcpy(params.prefix_mask, g_prefix_mask, 5 * sizeof(uint32_t));

	cl_mem paramBuf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
		sizeof(params), &params, &err);
	CL_CHECK(err);

	cl_mem foundBuf = clCreateBuffer(context, CL_MEM_READ_WRITE,
		sizeof(int), NULL, &err);
	CL_CHECK(err);

	// Initialize nonces
	vector<uint8_t> h_nonces(NUM_THREADS * NONCE_LEN);
	for (int i = 0; i < NUM_THREADS; i++)
		init_nonce(h_nonces.data() + i * NONCE_LEN, NONCE_LEN);
	CL_CHECK(clEnqueueWriteBuffer(queue, nonceBuf, CL_TRUE, 0,
		NUM_THREADS * NONCE_LEN, h_nonces.data(), 0, NULL, NULL));

	// Initialize results to 0xff
	vector<uint32_t> h_results(NUM_THREADS * 5, 0xffffffff);
	CL_CHECK(clEnqueueWriteBuffer(queue, resultBuf, CL_TRUE, 0,
		NUM_THREADS * 5 * sizeof(uint32_t), h_results.data(), 0, NULL, NULL));

	// Set kernel arguments
	CL_CHECK(clSetKernelArg(kernel, 0, sizeof(cl_mem), &dataBuf));
	CL_CHECK(clSetKernelArg(kernel, 1, sizeof(cl_mem), &stateBuf));
	CL_CHECK(clSetKernelArg(kernel, 2, sizeof(cl_mem), &nonceBuf));
	CL_CHECK(clSetKernelArg(kernel, 3, sizeof(cl_mem), &resultBuf));
	CL_CHECK(clSetKernelArg(kernel, 4, sizeof(cl_mem), &bestNonceBuf));
	CL_CHECK(clSetKernelArg(kernel, 5, sizeof(cl_mem), &paramBuf));
	CL_CHECK(clSetKernelArg(kernel, 6, sizeof(cl_mem), &foundBuf));

	// Time measurement
	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0, processed_last = 0;
	char buf[1000];
	bool found = false;

	log_msg("Launching OpenCL compute");

	for (;;) {
		// Reset found flag
		int h_found_flag = 0;
		CL_CHECK(clEnqueueWriteBuffer(queue, foundBuf, CL_TRUE, 0,
			sizeof(int), &h_found_flag, 0, NULL, NULL));

		// Enqueue kernel
		size_t global_size = (size_t)NUM_THREADS;
		size_t local_size = workgroup_size;
		CL_CHECK(clEnqueueNDRangeKernel(queue, kernel, 1, NULL,
			&global_size, &local_size, 0, NULL, NULL));
		CL_CHECK(clFinish(queue));

		processed += (uint64_t)NUM_THREADS * EPOCH_COUNT * (range_upper - range_lower + 1);

		// Read back results
		CL_CHECK(clEnqueueReadBuffer(queue, resultBuf, CL_TRUE, 0,
			NUM_THREADS * 5 * sizeof(uint32_t), h_results.data(), 0, NULL, NULL));
		vector<uint8_t> h_best_nonces(NUM_THREADS * NONCE_LEN);
		CL_CHECK(clEnqueueReadBuffer(queue, bestNonceBuf, CL_TRUE, 0,
			NUM_THREADS * NONCE_LEN, h_best_nonces.data(), 0, NULL, NULL));

		if (g_prefix_mode) {
			// Check found flag
			CL_CHECK(clEnqueueReadBuffer(queue, foundBuf, CL_TRUE, 0,
				sizeof(int), &h_found_flag, 0, NULL, NULL));
		}

		for (int i = 0; i < NUM_THREADS; i++) {
			if (g_prefix_mode) {
				// In prefix mode, check if this thread found a match
				bool match = true;
				for (int k = 0; k < 5; k++) {
					if ((h_results[i * 5 + k] & g_prefix_mask[k]) != g_prefix[k]) {
						match = false;
						break;
					}
				}
				if (match) {
					memcpy(RESULT_LOWEST, h_results.data() + i * 5, 5 * 4);
					memcpy(DATA_LOWEST.data() + g_nonce_start, h_best_nonces.data() + i * NONCE_LEN, NONCE_LEN);

					char buf_nonce[256];
					for (uint32_t j = 0; j < NONCE_LEN; j++)
						buf_nonce[j] = DATA_LOWEST[g_nonce_start + j];
					buf_nonce[NONCE_LEN] = 0;
					snprintf(buf, sizeof(buf), "Found prefix match: %08x%08x%08x%08x%08x (nonce: %s)",
						RESULT_LOWEST[0], RESULT_LOWEST[1], RESULT_LOWEST[2],
						RESULT_LOWEST[3], RESULT_LOWEST[4], buf_nonce);
					log_msg(buf);

					ofstream file_out;
					file_out.open(filename_out, ios::out | ios::binary);
					file_out.write((char*)DATA_LOWEST.data(), DATA_LEN);
					file_out.close();

					found = true;
					break;
				}
			} else {
				if (is_lower_hash(h_results.data() + i * 5, RESULT_LOWEST)) {
					memcpy(RESULT_LOWEST, h_results.data() + i * 5, 5 * 4);
					memcpy(DATA_LOWEST.data() + g_nonce_start, h_best_nonces.data() + i * NONCE_LEN, NONCE_LEN);

					char buf_nonce[256];
					for (uint32_t j = 0; j < NONCE_LEN; j++)
						buf_nonce[j] = DATA_LOWEST[g_nonce_start + j];
					buf_nonce[NONCE_LEN] = 0;
					snprintf(buf, sizeof(buf), "Found new lowest value: %08x%08x%08x%08x%08x (nonce: %s)",
						RESULT_LOWEST[0], RESULT_LOWEST[1], RESULT_LOWEST[2],
						RESULT_LOWEST[3], RESULT_LOWEST[4], buf_nonce);
					log_msg(buf);

					ofstream file_out;
					file_out.open(filename_out, ios::out | ios::binary);
					file_out.write((char*)DATA_LOWEST.data(), DATA_LEN);
					file_out.close();

					if (g_target_zeros > 0 && has_leading_zeros(RESULT_LOWEST, g_target_zeros)) {
						found = true;
					}
				}
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

	// Cleanup
	clReleaseMemObject(dataBuf);
	clReleaseMemObject(stateBuf);
	clReleaseMemObject(nonceBuf);
	clReleaseMemObject(resultBuf);
	clReleaseMemObject(bestNonceBuf);
	clReleaseMemObject(paramBuf);
	clReleaseMemObject(foundBuf);
	clReleaseKernel(kernel);
	clReleaseProgram(program);
	clReleaseCommandQueue(queue);
	clReleaseContext(context);

	return 0;
}
