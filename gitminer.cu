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

//Suppress warning for Visual Studio
//#pragma warning(disable:4996)

//nonce range (characters to use)
#define range_lower 'a'
#define range_upper 'z' //inclusive

//nonce range (sequence in base.txt)
#define data_range_start 237
#define data_range_end 246

//variable part of nonce
#define data_range_len_var 6

#define data_len_max 320 //expected max length of input data

int logmode = 1;

#define rol(x, n) (((x)<<(n))|((x)>>(32-(n))))

#if BYTE_ORDER == LITTLE_ENDIAN
#define blk0(i) (w[i] = (rol(w[i],24)&0xff00ff00)|(rol(w[i],8)&0x00ff00ff)) //little endian system
#elif BYTE_ORDER == BIG_ENDIAN
#define blk0(i) w[i]
#endif

//#define blk0(i) w[i] //big endian system
//double messing-up of endianness with memcpy

#define blk(i) (w[i&0xf]=rol(w[(i+13)&0xf]^w[(i+8)&0xf]^w[(i+2)&0xf]^w[i&0xf],1))
#define R0(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk0(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R1(l,m,n,o,p,q) p+=((m&(n^o))^o)+blk(q)+0x5a827999+rol(l,5);m=rol(m,30);
#define R2(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0x6ed9eba1+rol(l,5);m=rol(m,30);
#define R3(l,m,n,o,p,q) p+=(((m|n)&o)|(m&n))+blk(q)+0x8f1bbcdc+rol(l,5);m=rol(m,30);
#define R4(l,m,n,o,p,q) p+=(m^n^o)+blk(q)+0xca62c1d6+rol(l,5);m=rol(m,30);

void log(string output);
__device__ inline void memcpy_device(uint8_t *destination, uint8_t *source, size_t num);
__device__ inline void memcpy_device(uint32_t *destination, uint32_t *source, size_t num);
__device__ inline void memset_device(uint8_t *ptr, int value, size_t num);


__device__ inline void sha1_expand(uint8_t *data, int *data_len) {
	uint64_t m1;
	uint32_t seq;

	//message length
	m1 = (uint64_t) (*data_len) * 8;
	data[*data_len] = 0x80;
	
	seq = (*data_len)+1;
	*data_len = ((*data_len)+8)/64*64+56;
	//padding
	memset_device(data+seq, 0x00, (*data_len)-seq);
	
	//fill data as big endian converted m1
	data[(*data_len)] = (m1 >> 56) & 0xff; data[++(*data_len)] = (m1 >> 48) & 0xff;
	data[++(*data_len)] = (m1 >> 40) & 0xff; data[++(*data_len)] = (m1 >> 32) & 0xff;
	data[++(*data_len)] = (m1 >> 24) & 0xff; data[++(*data_len)] = (m1 >> 16) & 0xff;
	data[++(*data_len)] = (m1 >> 8) & 0xff; data[++(*data_len)] = (m1) & 0xff;
	
	++(*data_len);
}

__device__ inline void sha1_block(uint8_t *data_block, uint32_t *result) {
	uint32_t a, b, c, d, e; //temp variables
	uint32_t w[16]; //words
	memcpy_device(w, (uint32_t*) data_block, 64); //memcpy messes about the endianness.

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

__device__ inline void sha1_init(uint32_t *result) {
	result[0] = 0x67452301;
	result[1] = 0xefcdab89;
	result[2] = 0x98badcfe;
	result[3] = 0x10325476;
	result[4] = 0xc3d2e1f0;
}

__device__ inline void sha1_compute(uint8_t *data, int data_len, uint32_t *result) {
	sha1_init(result);

	for (int i = 0; i < data_len; i += 64) {
		sha1_block(data+i, result);
	}
}

__device__ inline void sha1(uint8_t *data, int data_len, uint32_t *result) {
	sha1_expand(data, &data_len);
	sha1_compute(data, data_len, result);
}

//default memcpy() implementation of CUDA kernel is very slow.
__device__ inline void memcpy_device(uint8_t *destination, uint8_t *source, size_t num) {
	for (int i = 0; i < num; ++i) {
		destination[i] = source[i];
	}
}

__device__ inline void memcpy_device(uint32_t *destination, uint32_t *source, size_t num) {
	for (int i = 0; i < num; ++i) {
		destination[i] = source[i];
	}
}

__device__ inline void memset_device(uint8_t *ptr, int value, size_t num) {
	for (int i = 0; i < num; ++i) {
		ptr[i] = value;
	}
}

__global__ void run_set(uint8_t *data_input, uint8_t *nonce, uint8_t *nonce_found, uint32_t *result_found, int data_len, int data_len_padded, int nonce_len, int epoch_count) {
	int kernel_id = blockIdx.x * blockDim.x + threadIdx.x;
	int nonce_size = data_range_end-data_range_start;

	//variable to perform search
	int range_search;
	int data_len_original = data_len;

	//pointers for current thread
	uint8_t data[data_len_max];
	//dynamic memory allocation in CUDA kernel is very slow because dynamically allocated array is not loaded onto register file.
	memcpy_device(data, data_input, data_len);
	memcpy_device(data+data_range_start, nonce+nonce_size*kernel_id, nonce_size);
	uint32_t result_cache[5];
	uint32_t result[5];

	//pad the data
	sha1_expand(data, &data_len);
	//pre-compute temporary value without last 64bits of data.
	sha1_compute(data, data_len_original-64, result_cache);
	//cache the temporary value
	for(int i = 0; i < epoch_count; ++i) {
		//calculate the least significant nonce via for loop to increase the performance.
		for(int j = range_lower; j < range_upper; ++j) {
			data[data_range_start] = j;
			memcpy_device(result, result_cache, 5*4);
			sha1_block(data+data_len-64, result);

			if (!result[0]) {
				if (result[1] < result_found[kernel_id*5+1]) {
					memcpy_device(nonce_found+kernel_id*nonce_len, data+data_range_start, nonce_len);
					memcpy_device(result_found+kernel_id*5, result, 5*4);
				}
			}
		}

		//calculate the next nonce
		range_search = data_range_start+1;
		data[data_range_start+1]++;
		while (data[range_search] > range_upper) {
			data[range_search] = range_lower;
			range_search++;
			data[range_search]++;
		}
	}

	memcpy_device(nonce + nonce_size*kernel_id, data+data_range_start, nonce_size);
}

//initializa variables for CUDA device
void init_nonce(uint8_t *nonce) {
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> dist(range_lower, range_upper);

	//random nonce for each kernel
	for (int i = data_range_len_var; i < data_range_end - data_range_start; ++i) {
		nonce[i] = (uint8_t) dist(mt);
	}
	for (int i = 0; i < data_range_len_var; ++i) {
		nonce[i] = (uint8_t) range_lower;
	}
}

string filename_log, filename_out;

void log(string output) {
	ofstream file_log;
	file_log.open(filename_log, ios::out | ios::app); 
	file_log<<output<<endl;
	if (logmode) {
		cout<<output<<endl;
	}
	file_log.close();
}

void output(uint8_t *data, uint32_t data_len) {
	ofstream file_out;
	file_out.open(filename_out, ios::out | ios::binary); 
	file_out.write((char*)data, data_len);
	file_out.close();
}

int main(int argc, char *argv[]) {
	uint8_t *DATA;
	uint32_t RESULT_LEAST[5] = {0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff};
	uint8_t *DATA_LEAST;
	uint32_t DATA_LEN, PADDED_LEN;

	char buf[1000], buf_nonce[1000];

	int NUM_BLOCKS = 136, NUM_THREADS = 256;
	int EPOCH_COUNT = 100000;

	log("Reading data");

	//read file
	ifstream file_base;
	file_base.open("base.txt", ios::in | ios::binary | ios::ate); 
	if (!file_base.is_open()) {
		log("base.txt not exist.");
		return 0;
	}
	DATA_LEN = file_base.tellg();
	
	//calculate length after padding (to allocate memory)
	if (DATA_LEN % 64 <= 55) {
		PADDED_LEN = DATA_LEN/64*64 + 64;
	} else if (DATA_LEN % 64 > 55) {
		PADDED_LEN = DATA_LEN/64*64 + 128;
	}
	
	DATA = (uint8_t*) calloc(DATA_LEN, sizeof(uint8_t));
	DATA_LEAST = (uint8_t*) calloc(DATA_LEN, sizeof(uint8_t));

	file_base.seekg(0, ios::beg);
	file_base.read((char*)DATA, DATA_LEN);
	file_base.close();
	log ("Read " + to_string(DATA_LEN) + " bytes.");

	int device_count;
	cudaGetDeviceCount(&device_count);
	log(to_string(device_count) + " CUDA capable device(s) found");

	if (argc > 1) {
		cudaSetDevice(atoi(argv[1]));
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
	
	log("Starting");

	log("Allocating memory...");

	uint32_t NONCE_LEN = data_range_end - data_range_start;
	uint8_t *NONCE_TEMP, *NONCE_THREAD, *NONCE_THREAD_LEAST, *BASE;
	uint32_t *RESULT_THREAD_LEAST_TEMP, *RESULT_THREAD_LEAST;

	cudaMallocHost(&NONCE_TEMP, NUM_BLOCKS*NUM_THREADS*NONCE_LEN);
	cudaMalloc(&NONCE_THREAD, NUM_BLOCKS*NUM_THREADS*NONCE_LEN);
	cudaMalloc(&NONCE_THREAD_LEAST, NUM_BLOCKS*NUM_THREADS*NONCE_LEN);
	cudaMalloc(&BASE, DATA_LEN);
	cudaMallocHost(&RESULT_THREAD_LEAST_TEMP, NUM_BLOCKS*NUM_THREADS*5*4);
	cudaMalloc(&RESULT_THREAD_LEAST, NUM_BLOCKS*NUM_THREADS*5*4);

	log("Initializing memory");
	for (int i = 0; i < NUM_BLOCKS*NUM_THREADS; ++i) {
		init_nonce(NONCE_TEMP + i*NONCE_LEN);
	}
	memset(RESULT_THREAD_LEAST_TEMP, 0xff, NUM_BLOCKS*NUM_THREADS*5*4);
	memcpy(DATA_LEAST, DATA, DATA_LEN);
	log("Copying memory");
	cudaMemcpy(NONCE_THREAD, NONCE_TEMP, NUM_BLOCKS*NUM_THREADS*NONCE_LEN, cudaMemcpyHostToDevice);
	cudaMemcpy(BASE, DATA, DATA_LEN, cudaMemcpyHostToDevice);
	cudaMemcpy(RESULT_THREAD_LEAST, RESULT_THREAD_LEAST_TEMP, NUM_BLOCKS*NUM_THREADS*5*4, cudaMemcpyHostToDevice);
	cudaDeviceSynchronize();

	//time measurement
	auto begin = chrono::high_resolution_clock::now();
	auto begin_log = chrono::high_resolution_clock::now();
	uint64_t processed = 0;
	uint64_t processed_last = 0;

	auto end = chrono::high_resolution_clock::now();
	auto elapsed = begin-end, elapsed_last = begin-end, elapsed_log = begin-end;

	log("Launching CUDA kernels");

	for(;;) {
		run_set<<<NUM_BLOCKS, NUM_THREADS>>>(BASE, NONCE_THREAD, NONCE_THREAD_LEAST, RESULT_THREAD_LEAST, DATA_LEN, PADDED_LEN, NONCE_LEN, EPOCH_COUNT);

		processed += (uint64_t) NUM_BLOCKS * NUM_THREADS * EPOCH_COUNT * (range_upper - range_lower + 1);

		cudaMemcpy(RESULT_THREAD_LEAST_TEMP, RESULT_THREAD_LEAST, NUM_BLOCKS*NUM_THREADS*5*4, cudaMemcpyDeviceToHost);

		for (uint64_t i = 0; i < (uint64_t) NUM_BLOCKS*NUM_THREADS; ++i) {
			if (!RESULT_THREAD_LEAST_TEMP[5*i+0]) {
				if (RESULT_THREAD_LEAST_TEMP[5*i+1] < RESULT_LEAST[1]) {
					memcpy(RESULT_LEAST, RESULT_THREAD_LEAST_TEMP+5*i, 5*4);
					cudaMemcpy(DATA_LEAST+data_range_start, NONCE_THREAD_LEAST+NONCE_LEN*i, NONCE_LEN, cudaMemcpyDeviceToHost);
					for (int j = 0; j < NONCE_LEN; ++j) {
						buf_nonce[j] = DATA_LEAST[data_range_start+j];
					}
					buf_nonce[NONCE_LEN] = 0;
					sprintf(buf, "Thread #%ld found the least value: %08x%08x%08x%08x%08x (nonce: %s)", i, RESULT_LEAST[0], RESULT_LEAST[1], RESULT_LEAST[2], RESULT_LEAST[3], RESULT_LEAST[4], buf_nonce);
					log(buf);
					output(DATA_LEAST, DATA_LEN);
				}
			}
		}
		end = chrono::high_resolution_clock::now();
		elapsed_log = chrono::duration_cast<chrono::nanoseconds>(end - begin_log);
		if (1e9*10 < (double)elapsed_log.count()) {
			elapsed = chrono::duration_cast<chrono::nanoseconds>(end - begin);
			sprintf(buf, "Processed %ldG hashes (%.2fMH/s)\n", processed/1000000000, (1e3*(processed-processed_last)/(elapsed.count()-elapsed_last.count())));
			elapsed_last = elapsed;
			processed_last = processed;
			log(buf);
			begin_log = chrono::high_resolution_clock::now();
		}
	}
}