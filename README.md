# gitminer-cuda

GPU-accelerated git commit hash miner. Finds nonces that produce SHA-1 commit hashes with maximum leading hex zeros, a specific hex prefix, or the lowest possible hash value.

## Backends

| Backend | Platform | Build Target |
|---|---|---|
| **CUDA** | NVIDIA GPUs | `make gitminer` |
| **Metal** | Apple Silicon (macOS) | `make gitminer_metal` |
| **OpenCL** | Cross-platform GPU | `make gitminer_opencl` |
| **Vulkan** | Cross-platform GPU | `make gitminer_vulkan` |
| **CPU** | Any platform | `make gitminer_cpu` |

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

## Quick Start

The easiest way to use gitminer is through `mine_commit.sh`, which handles all the details of preparing the commit object, running the miner, and applying the result:

```sh
# Build a miner backend
make gitminer_metal

# Make a commit, then mine it for 7 leading hex zeros
git commit -m "my commit"
./mine_commit.sh 7
```

For automatic mining after every commit, install as a git hook:

```sh
cp mine_commit.sh .git/hooks/post-commit
chmod +x .git/hooks/post-commit
```

## mine_commit.sh

`mine_commit.sh` is the main interface for mining commits. It handles GPG-signed and unsigned commits, auto-detects the best available miner backend, and supports three mining modes.

### Modes

```sh
# Leading zeros mode (default): mine for N leading hex zeros
mine_commit.sh [target_zeros] [threads]
mine_commit.sh 7 12         # 7 leading zeros, 12 threads

# Infinite mode: run forever finding the lowest possible hash
# Press Ctrl+C to stop and apply the best result found so far
mine_commit.sh infinite [threads]
mine_commit.sh infinite 12

# Incremental mode: auto-generate sequential hex prefix per commit
# First commit -> 0000000, second -> 0000001, ..., 11th -> 000000a, etc.
mine_commit.sh incremental [prefix_length] [threads]
mine_commit.sh incremental 7 12   # 7-digit prefix, 12 threads
```

| Mode | Description | Terminates? |
|---|---|---|
| `[target_zeros]` | Mine for N leading hex zeros (default: 7) | Yes, when target reached |
| `infinite` | Find the lowest possible hash | No, runs until Ctrl+C |
| `incremental` | Sequential hex prefix based on commit number (0-indexed) | Yes, when prefix matched |

### Miner Auto-Detection

The script auto-detects the best available backend in priority order:

CUDA > Vulkan > Metal > OpenCL > CPU

### How the Hook Works

- **Unsigned commits**: appends `nonce:<random>` to the commit message, then mines for the target
- **GPG-signed commits**: injects a `Comment: nonce=<random>` line into the PGP armor block. This field is ignored by GPG signature verification but is part of the git object hash, so the signature remains valid after mining

### Setup as Post-Commit Hook

```sh
# 1. Build the miner (pick your backend)
make gitminer_metal   # macOS with Apple Silicon
make gitminer_opencl  # macOS/Linux with OpenCL GPU
make gitminer_cpu     # any platform

# 2. Install as post-commit hook in your repo
cp mine_commit.sh /path/to/your/repo/.git/hooks/post-commit
chmod +x /path/to/your/repo/.git/hooks/post-commit
```

### Global Setup (All Repos)

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

## Direct Miner Usage

For advanced usage, the miner backends can be called directly. This requires preparing a `base.txt` input file.

### Command Line Arguments

```sh
./gitminer       <gpu_id>      <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [num_blocks] [target_prefix]
./gitminer_metal <ignored>     <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_opencl <device_id>  <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_vulkan <device_id>  <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
./gitminer_cpu   <num_threads> <log_file> <result_file> <nonce_start> <nonce_end> <target_zeros> [target_prefix]
```

| Argument | Description |
|---|---|
| `gpu_id` / `device_id` | GPU device index (0-based) |
| `num_threads` | CPU thread count |
| `log_file` | Path to log file (use `/dev/stderr` for console output) |
| `result_file` | Path to write the mined commit object |
| `nonce_start` | Byte offset where the nonce begins in `base.txt` |
| `nonce_end` | Byte offset where the nonce ends in `base.txt` |
| `target_zeros` | Number of leading hex zeros to find (0 = find lowest hash forever) |
| `num_blocks` | CUDA grid blocks (CUDA only, default: 1024) |
| `target_prefix` | Exact hex prefix to match (overrides `target_zeros`) |

### Preparing base.txt

The miner reads a file called `base.txt` which must contain a complete git commit object including the git object header. The format is:

```
commit <content_length>\0<commit_content>
```

Where `<content_length>` is the decimal byte count of `<commit_content>`, and `\0` is a null byte. The commit content must contain a nonce region (a run of placeholder characters in the range `[nonce_start, nonce_end)`) that the miner will overwrite with random `a-z` characters.

#### Example: Manual Preparation

```sh
# 1. Get raw commit content
CONTENT=$(git cat-file commit HEAD)
CONTENT_LEN=$(printf '%s' "$CONTENT" | wc -c | tr -d ' ')

# 2. Write as git object (header + null byte + content)
printf "commit %d\0%s" "$CONTENT_LEN" "$CONTENT" > base.txt

# 3. Find the nonce position (byte offset of the placeholder in base.txt)
python3 -c "
data = open('base.txt', 'rb').read()
pos = data.find(b'aaaaaaaaaa')  # your nonce placeholder
print(pos)
"

# 4. Run the miner
./gitminer_metal 0 /dev/stderr result.txt <nonce_start> <nonce_end> 7

# 5. Apply the result
python3 -c "
data = open('result.txt', 'rb').read()
null_pos = data.index(b'\x00')
open('commit_content.tmp', 'wb').write(data[null_pos+1:])
"
NEW_HASH=$(git hash-object -t commit -w commit_content.tmp)
git update-ref refs/heads/$(git branch --show-current) "$NEW_HASH"
```

### Mining Modes

**Lowest hash mode** (`target_zeros=0`, no prefix): The miner runs indefinitely, continuously finding lower hash values. Each improvement is written to `result_file`. The miner never exits on its own.

**Leading zeros mode** (`target_zeros=N`): The miner finds the lowest hash and exits once it has at least N leading hex zeros.

**Prefix mode** (`target_prefix=<hex>`): The miner searches for a hash starting with the exact hex prefix and exits immediately when found.

### Environment Variables

| Variable | Backend | Description |
|---|---|---|
| `GPU_THREADS` | Metal | Override GPU thread count (default: 65536) |

## How It Works

1. Reads a git commit object from `base.txt` (with git object header `commit <len>\0`)
2. Replaces characters in the nonce region `[nonce_start, nonce_end)` with random `a-z` characters
3. Computes SHA-1 hashes across all nonce candidates in parallel on the GPU
4. Pre-computes SHA-1 state for all blocks before the nonce position to avoid redundant work
5. Keeps the nonce producing the best hash (lowest value, or matching a target prefix)
6. Writes the full modified commit object (with header) to `result_file`

GPG-signed commits are supported via a PGP armor `Comment` field used as the nonce carrier. GPG ignores armor comment headers during signature verification, so the signature remains valid.

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
- Metal kernel: 65,536 GPU threads (256 per threadgroup), configurable via `GPU_THREADS` env var
- Data center GPUs (H100, A100) have lower INT32 throughput than consumer GPUs due to lower clock speeds (H100: 1980 MHz, A100: 1410 MHz vs RTX 4090: 2520 MHz), despite having more SMs
