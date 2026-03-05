# gitminer-cuda

GPU-accelerated git commit hash miner. Finds nonces that produce SHA-1 commit hashes with maximum leading hex zeros or a specific hex prefix.

## Backends

- **CUDA** - NVIDIA GPUs
- **Metal** - Apple Silicon (macOS only)
- **OpenCL** - Cross-platform GPU (macOS, Linux, Windows)
- **Vulkan** - Cross-platform GPU (requires Vulkan SDK)
- **CPU** - Multi-threaded, any platform

## Build

```sh
# CUDA (requires CUDA toolkit and nvcc)
make gitminer

# Metal (macOS only)
make gitminer_metal

# OpenCL (macOS: built-in, Linux: requires OpenCL SDK)
make gitminer_opencl

# Vulkan (requires Vulkan SDK and glslc)
make gitminer_vulkan

# CPU
make gitminer_cpu
```

## Usage

```sh
./gitminer <gpu_id> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [num_blocks] [target_prefix]
./gitminer_metal <ignored> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_opencl <device_id> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_vulkan <device_id> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_cpu <num_threads> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
```

All backends read `base.txt` (raw git commit object with header) and write the modified commit object to `result_file`.

### Prefix Mode

When `target_prefix` is specified, the miner searches for a hash starting with that exact hex prefix instead of finding the lowest hash:

```sh
# Find a hash starting with "deadbee" (7 hex digits)
./gitminer_metal 0 /dev/stderr result.txt 235 245 0 deadbee

# Find a hash starting with "cafebabe" (8 hex digits)
./gitminer_cpu 8 /dev/stderr result.txt 235 245 0 cafebabe
```

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
| NVIDIA H100 SXM5 80GB | CUDA | 21.6 GH/s |
| NVIDIA A100 PCIe 80GB | CUDA | 12.2 GH/s |
| NVIDIA A100 PCIe 40GB | CUDA | 11.9 GH/s |
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
- Data center GPUs (H100, A100) have lower INT32 throughput than consumer GPUs due to lower clock speeds (H100: 1980 MHz, A100: 1410 MHz vs RTX 4090: 2520 MHz), despite having more SMs

## Setup as Post-Commit Hook

`mine_commit.sh` automatically mines each commit after it is created. It works with both GPG-signed and unsigned commits.

### Quick Setup

```sh
# 1. Build the miner (pick your backend)
make gitminer_metal   # macOS with Apple Silicon
make gitminer_opencl  # macOS/Linux with OpenCL GPU
make gitminer_cpu     # any platform

# 2. Install as post-commit hook in your repo
cp mine_commit.sh /path/to/your/repo/.git/hooks/post-commit
chmod +x /path/to/your/repo/.git/hooks/post-commit
```

### How the Hook Works

- **Unsigned commits**: appends `nonce:<random>` to the commit message, then mines for leading zeros
- **GPG-signed commits**: injects a `Comment: nonce=<random>` line into the PGP armor block. This field is ignored by GPG signature verification but is part of the git object hash, so the signature remains valid after mining

The hook auto-detects the best available backend: Metal GPU > OpenCL GPU > CPU.

### Configuration

Edit the hook script or pass arguments:

```sh
# In .git/hooks/post-commit:
TARGET_ZEROS=7      # number of leading hex zeros (default: 7)
THREADS=12          # CPU threads (default: auto-detect)
```

### Global Setup (All Repos)

To enable mining for all git repositories:

```sh
# 1. Create a global hooks directory
mkdir -p ~/.config/git/hooks

# 2. Copy the hook and miner
cp mine_commit.sh ~/.config/git/hooks/post-commit
chmod +x ~/.config/git/hooks/post-commit
cp gitminer_metal ~/.config/git/hooks/   # or gitminer_cpu, gitminer_opencl

# 3. Configure git to use global hooks
git config --global core.hooksPath ~/.config/git/hooks
```
