# gitminer-cuda

GPU-accelerated git commit hash miner. Finds nonces that produce SHA-1 commit hashes with maximum leading hex zeros.

## Backends

- **CUDA** - NVIDIA GPUs
- **Metal** - Apple Silicon (macOS only)
- **CPU** - Multi-threaded, any platform

## Build

```sh
# CUDA (requires CUDA toolkit and nvcc)
make gitminer

# Metal (macOS only)
make gitminer_metal

# CPU
make gitminer_cpu
```

## Usage

```sh
./gitminer <gpu_id> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros>
./gitminer_metal <ignored> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros>
./gitminer_cpu <num_threads> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros>
```

All backends read `base.txt` (raw git commit object with header) and write the modified commit object to `result_file`.

## How It Works

1. Reads a git commit object from `base.txt`
2. Replaces characters in the range `[nonce_start, nonce_end)` with random `a-z` characters
3. Computes SHA-1 hashes across all nonce candidates, keeping the one producing the lowest (most leading zeros) hash
4. Pre-computes SHA-1 state for all SHA-1 blocks before the nonce position to avoid redundant work
5. `mine_commit.sh` can be used as a post-commit hook for automatic mining after each commit

GPG-signed commits are supported via a PGP armor `Comment` field used as the nonce carrier.

## Benchmark Results

Measured with a 244-byte test commit object (1 remaining SHA-1 block after pre-computation).

| Platform | Backend | Hash Rate |
|---|---|---|
| NVIDIA RTX 5090 | CUDA | 46.9 GH/s |
| NVIDIA RTX 4090 | CUDA | 27.5 GH/s |
| NVIDIA RTX 2080 Ti | CUDA | 9.0 GH/s |
| Apple M4 Pro | Metal | 2.3 GH/s |
| AMD EPYC 7352 (48 threads) | CPU | ~500 MH/s |
| AMD Ryzen 7 9700X (16 threads) | CPU | ~174 MH/s |
| Apple M4 Pro (12 threads) | CPU | ~159 MH/s |

Notes:

- RTX 5090 processed 817B SHA-1 hashes in 30s (1.7x faster than RTX 4090)
- Hash rate scales inversely with commit object size (more SHA-1 blocks per hash)
- CUDA kernel: 1024 blocks x 256 threads = 262,144 threads
- Metal kernel: 65,536 GPU threads (256 per threadgroup)

## Integration

`mine_commit.sh` is designed to be used as a git `post-commit` hook. It auto-detects available backends, preferring Metal over CPU with automatic fallback, and rewrites the most recent commit with the best nonce found.

To install:

```sh
cp mine_commit.sh .git/hooks/post-commit
chmod +x .git/hooks/post-commit
```
