#import <Metal/Metal.h>
#import <Foundation/Foundation.h>
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

inline bool matches_prefix(const uint32_t *hash, const uint32_t *prefix, const uint32_t *mask) {
	for (int i = 0; i < 5; i++)
		if ((hash[i] & mask[i]) != prefix[i]) return false;
	return true;
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

// ── Metal Shader Source ──────────────────────────────────────────────

static const char *metalShaderSource = R"(
#include <metal_stdlib>
using namespace metal;

#define RANGE_LOWER 97
#define RANGE_UPPER 122

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

void sha1_block_impl(thread uint8_t *data_block, thread uint32_t *result) {
	uint32_t a, b, c, d, e;
	uint32_t w[16];
	for (int i = 0; i < 16; i++) {
		uint idx = i * 4;
		w[i] = ((uint32_t)data_block[idx]) | ((uint32_t)data_block[idx+1] << 8)
			 | ((uint32_t)data_block[idx+2] << 16) | ((uint32_t)data_block[idx+3] << 24);
	}

	// blk0: little-endian byte swap
	for (int i = 0; i < 16; i++)
		w[i] = (rol(w[i],24)&0xff00ff00)|(rol(w[i],8)&0x00ff00ff);

	a = result[0]; b = result[1]; c = result[2]; d = result[3]; e = result[4];

	// Rounds 0-15 (use w directly, already swapped)
	#define F0(l,m,n,o,p,q) p+=((m&(n^o))^o)+w[q]+0x5a827999+rol(l,5);m=rol(m,30);
	F0(a,b,c,d,e,0);  F0(e,a,b,c,d,1);  F0(d,e,a,b,c,2);  F0(c,d,e,a,b,3);
	F0(b,c,d,e,a,4);  F0(a,b,c,d,e,5);  F0(e,a,b,c,d,6);  F0(d,e,a,b,c,7);
	F0(c,d,e,a,b,8);  F0(b,c,d,e,a,9);  F0(a,b,c,d,e,10); F0(e,a,b,c,d,11);
	F0(d,e,a,b,c,12); F0(c,d,e,a,b,13); F0(b,c,d,e,a,14); F0(a,b,c,d,e,15);

	// blk expansion + rounds 16-79
	#define BLK(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
	#define G1(l,m,n,o,p,q) p+=((m&(n^o))^o)+BLK(q)+0x5a827999+rol(l,5);m=rol(m,30);
	#define G2(l,m,n,o,p,q) p+=(m^n^o)+BLK(q)+0x6ed9eba1+rol(l,5);m=rol(m,30);
	#define G3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+BLK(q)+0x8f1bbcdc+rol(l,5);m=rol(m,30);
	#define G4(l,m,n,o,p,q) p+=(m^n^o)+BLK(q)+0xca62c1d6+rol(l,5);m=rol(m,30);

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

struct MineParams {
	uint nonce_start;
	uint nonce_end;
	uint epoch_count;
	uint nonce_block_start;
	uint padded_len;
	uint nonce_size;
	uint prefix_mode;
	uint prefix0; uint prefix1; uint prefix2; uint prefix3; uint prefix4;
	uint mask0; uint mask1; uint mask2; uint mask3; uint mask4;
};

kernel void mine_sha1(
	device const uint8_t *data_padded [[buffer(0)]],
	constant uint32_t *state_cache [[buffer(1)]],
	device uint8_t *nonces [[buffer(2)]],
	device uint32_t *best_results [[buffer(3)]],
	device uint8_t *best_nonces [[buffer(4)]],
	constant MineParams &params [[buffer(5)]],
	device atomic_uint *found_flag [[buffer(6)]],
	uint tid [[thread_position_in_grid]]
) {
	uint nonce_start = params.nonce_start;
	uint nonce_size = params.nonce_size;
	uint epoch_count = params.epoch_count;
	uint nonce_block_start = params.nonce_block_start;
	uint padded_len = params.padded_len;
	uint nonce_offset = nonce_start - nonce_block_start;

	// Load per-thread nonce
	uint8_t my_nonce[32];
	for (uint i = 0; i < nonce_size; i++)
		my_nonce[i] = nonces[tid * nonce_size + i];

	// Load nonce block template (64 bytes)
	uint8_t nonce_block[64];
	for (int i = 0; i < 64; i++)
		nonce_block[i] = data_padded[nonce_block_start + i];
	// Overlay nonce
	for (uint i = 0; i < nonce_size; i++)
		nonce_block[nonce_offset + i] = my_nonce[i];

	// Local best
	uint32_t local_best[5];
	for (int i = 0; i < 5; i++) local_best[i] = best_results[tid * 5 + i];
	uint8_t local_best_nonce[32];
	for (uint i = 0; i < nonce_size; i++) local_best_nonce[i] = my_nonce[i];

	uint8_t temp_block[64];

	for (uint ep = 0; ep < epoch_count; ep++) {
		if (params.prefix_mode && atomic_load_explicit((device atomic_uint*)found_flag, memory_order_relaxed)) break;
		for (int j = RANGE_LOWER; j <= RANGE_UPPER; j++) {
			nonce_block[nonce_offset] = (uint8_t)j;

			// Restore cached state
			uint32_t result[5];
			for (int k = 0; k < 5; k++) result[k] = state_cache[k];

			// Process nonce block
			sha1_block_impl(nonce_block, result);

			// Process remaining blocks from device memory
			for (uint blk = nonce_block_start + 64; blk < padded_len; blk += 64) {
				for (int i = 0; i < 64; i++) temp_block[i] = data_padded[blk + i];
				sha1_block_impl(temp_block, result);
			}

			// Check if lower or prefix match
			if (params.prefix_mode) {
				uint prefix_arr[5] = {params.prefix0, params.prefix1, params.prefix2, params.prefix3, params.prefix4};
				uint mask_arr[5] = {params.mask0, params.mask1, params.mask2, params.mask3, params.mask4};
				bool match = true;
				for (int k = 0; k < 5; k++) {
					if ((result[k] & mask_arr[k]) != prefix_arr[k]) { match = false; break; }
				}
				if (match) {
					for (int k = 0; k < 5; k++) local_best[k] = result[k];
					local_best_nonce[0] = (uint8_t)j;
					for (uint i = 1; i < nonce_size; i++) local_best_nonce[i] = my_nonce[i];
					atomic_store_explicit((device atomic_uint*)found_flag, 1, memory_order_relaxed);
				}
			} else {
				bool lower = false;
				for (int k = 0; k < 5; k++) {
					if (result[k] < local_best[k]) { lower = true; break; }
					if (result[k] > local_best[k]) { break; }
				}
				if (lower) {
					for (int k = 0; k < 5; k++) local_best[k] = result[k];
					local_best_nonce[0] = (uint8_t)j;
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

// ── Main ─────────────────────────────────────────────────────────────

int main(int argc, char *argv[]) {
	@autoreleasepool {

	uint32_t RESULT_LOWEST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint32_t DATA_LEN;

	int NUM_THREADS = 65536;
	int EPOCH_COUNT = 100;

	// argv[1] is ignored (CPU thread count for compatibility); Metal always uses NUM_THREADS GPU threads
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

	// ── Metal setup ──
	id<MTLDevice> device = MTLCreateSystemDefaultDevice();
	if (!device) { log_msg("Metal not available."); return 1; }
	log_msg("Metal device: " + string([[device name] UTF8String]));

	id<MTLCommandQueue> commandQueue = [device newCommandQueue];

	NSError *error = nil;
	MTLCompileOptions *options = [[MTLCompileOptions alloc] init];
	options.mathMode = MTLMathModeFast;
	id<MTLLibrary> library = [device newLibraryWithSource:
		[NSString stringWithUTF8String:metalShaderSource] options:options error:&error];
	if (!library) {
		log_msg("Shader compile error: " + string([[error localizedDescription] UTF8String]));
		return 1;
	}

	id<MTLFunction> kernelFunc = [library newFunctionWithName:@"mine_sha1"];
	if (!kernelFunc) { log_msg("Kernel function not found"); return 1; }

	id<MTLComputePipelineState> pipeline = [device newComputePipelineStateWithFunction:kernelFunc error:&error];
	if (!pipeline) { log_msg("Pipeline error"); return 1; }

	NSUInteger maxThreadsPerGroup = [pipeline maxTotalThreadsPerThreadgroup];
	NSUInteger threadgroupSize = min((NSUInteger)256, maxThreadsPerGroup);

	log_msg("Using " + to_string(NUM_THREADS) + " GPU threads (" +
		to_string(threadgroupSize) + " per threadgroup)");
	log_msg("Nonce region: [" + to_string(g_nonce_start) + ", " + to_string(g_nonce_end) + ")");
	if (g_target_zeros > 0)
		log_msg("Target: " + to_string(g_target_zeros) + " leading hex zeros");
	if (g_prefix_mode)
		log_msg("Target prefix: " + g_target_prefix_str);

	// Create buffers
	id<MTLBuffer> dataBuf = [device newBufferWithBytes:DATA.data()
		length:PADDED_LEN options:MTLResourceStorageModeShared];
	id<MTLBuffer> stateBuf = [device newBufferWithBytes:state_cache
		length:sizeof(state_cache) options:MTLResourceStorageModeShared];
	id<MTLBuffer> nonceBuf = [device newBufferWithLength:NUM_THREADS * NONCE_LEN
		options:MTLResourceStorageModeShared];
	id<MTLBuffer> resultBuf = [device newBufferWithLength:NUM_THREADS * 5 * sizeof(uint32_t)
		options:MTLResourceStorageModeShared];
	id<MTLBuffer> bestNonceBuf = [device newBufferWithLength:NUM_THREADS * NONCE_LEN
		options:MTLResourceStorageModeShared];
	id<MTLBuffer> foundBuf = [device newBufferWithLength:sizeof(uint32_t)
		options:MTLResourceStorageModeShared];

	struct {
		uint32_t nonce_start;
		uint32_t nonce_end;
		uint32_t epoch_count;
		uint32_t nonce_block_start;
		uint32_t padded_len;
		uint32_t nonce_size;
		uint32_t prefix_mode;
		uint32_t prefix0, prefix1, prefix2, prefix3, prefix4;
		uint32_t mask0, mask1, mask2, mask3, mask4;
	} params = {
		(uint32_t)g_nonce_start, (uint32_t)g_nonce_end,
		(uint32_t)EPOCH_COUNT, (uint32_t)nonce_block_start,
		PADDED_LEN, NONCE_LEN,
		(uint32_t)g_prefix_mode,
		g_prefix[0], g_prefix[1], g_prefix[2], g_prefix[3], g_prefix[4],
		g_prefix_mask[0], g_prefix_mask[1], g_prefix_mask[2], g_prefix_mask[3], g_prefix_mask[4]
	};
	id<MTLBuffer> paramBuf = [device newBufferWithBytes:&params
		length:sizeof(params) options:MTLResourceStorageModeShared];

	// Initialize nonces
	uint8_t *noncePtr = (uint8_t*)[nonceBuf contents];
	for (int i = 0; i < NUM_THREADS; i++)
		init_nonce(noncePtr + i * NONCE_LEN, NONCE_LEN);

	// Initialize results to 0xff
	memset([resultBuf contents], 0xff, NUM_THREADS * 5 * sizeof(uint32_t));

	// Time measurement
	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0, processed_last = 0;
	char buf[1000];
	bool found = false;

	log_msg("Launching Metal compute");

	for (;;) {
		@autoreleasepool {
			id<MTLCommandBuffer> cmdBuf = [commandQueue commandBuffer];
			id<MTLComputeCommandEncoder> encoder = [cmdBuf computeCommandEncoder];
			[encoder setComputePipelineState:pipeline];
			*(uint32_t*)[foundBuf contents] = 0;
			[encoder setBuffer:dataBuf offset:0 atIndex:0];
			[encoder setBuffer:stateBuf offset:0 atIndex:1];
			[encoder setBuffer:nonceBuf offset:0 atIndex:2];
			[encoder setBuffer:resultBuf offset:0 atIndex:3];
			[encoder setBuffer:bestNonceBuf offset:0 atIndex:4];
			[encoder setBuffer:paramBuf offset:0 atIndex:5];
			[encoder setBuffer:foundBuf offset:0 atIndex:6];

			MTLSize gridSize = MTLSizeMake(NUM_THREADS, 1, 1);
			MTLSize tgSize = MTLSizeMake(threadgroupSize, 1, 1);
			[encoder dispatchThreads:gridSize threadsPerThreadgroup:tgSize];
			[encoder endEncoding];
			[cmdBuf commit];
			[cmdBuf waitUntilCompleted];
		}

		processed += (uint64_t)NUM_THREADS * EPOCH_COUNT * (range_upper - range_lower + 1);

		// Read back results
		uint32_t *results = (uint32_t*)[resultBuf contents];
		uint8_t *bestNonces = (uint8_t*)[bestNonceBuf contents];

		for (int i = 0; i < NUM_THREADS; i++) {
			if (g_prefix_mode) {
				if (matches_prefix(results + i * 5, g_prefix, g_prefix_mask)) {
					memcpy(RESULT_LOWEST, results + i * 5, 5 * 4);
					memcpy(DATA_LOWEST.data() + g_nonce_start, bestNonces + i * NONCE_LEN, NONCE_LEN);

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
				}
			} else {
				if (is_lower_hash(results + i * 5, RESULT_LOWEST)) {
					memcpy(RESULT_LOWEST, results + i * 5, 5 * 4);
					memcpy(DATA_LOWEST.data() + g_nonce_start, bestNonces + i * NONCE_LEN, NONCE_LEN);

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

					if (g_target_zeros > 0 && has_leading_zeros(RESULT_LOWEST, g_target_zeros))
						found = true;
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

	} // autoreleasepool
	return 0;
}
