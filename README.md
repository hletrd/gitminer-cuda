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

| Platform | Backend | Hash Rate | Power | 7-zero time |
|---|---|---|---|---|
| RTX 4090 | CUDA | 27.5 GH/s | 449 W | < 1 s |
| EPYC 7352 (48 threads) | CPU | ~500 MH/s | - | ~0.5 s |
| Apple M4 Pro | Metal | 134 MH/s | ~15 W | ~3 s |

Notes:

- RTX 4090 achieves 100% GPU utilization (449 W / 450 W TDP)
- RTX 4090 found 9 leading zeros in under 5 seconds
- RTX 4090 processed 613 billion SHA-1 hashes in 30 seconds
- CUDA kernel: 1024 blocks x 256 threads = 262,144 threads
- Metal kernel: 65,536 GPU threads (256 per threadgroup)

## Integration

`mine_commit.sh` is designed to be used as a git `post-commit` hook. It auto-detects available backends, preferring Metal over CPU with automatic fallback, and rewrites the most recent commit with the best nonce found.

To install:

```sh
cp mine_commit.sh .git/hooks/post-commit
chmod +x .git/hooks/post-commit
```
