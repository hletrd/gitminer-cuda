#!/bin/bash
#
# mine_commit.sh - Mine a git commit hash with leading zeros
#
# Usage: mine_commit.sh [mode] [args...]
#
#   mine_commit.sh [target_zeros] [threads]
#     Mine for N leading hex zeros (default: 7).
#
#   mine_commit.sh infinite [threads]
#     Run forever finding the lowest possible hash.
#     Press Ctrl+C to stop and apply the best result found so far.
#
#   mine_commit.sh incremental [prefix_length] [threads]
#     Auto-generate a sequential hex prefix based on commit number.
#     First commit -> 0000000, second -> 0000001, ..., 11th -> 000000a, etc.
#     prefix_length: number of hex digits (default: 7)
#
#   threads: CPU threads / device ID to use (default: auto-detect)
#
# Must be run from within a git repository after making a commit.
# The most recent commit will be re-created with a nonce that produces
# a hash matching the target.
#
# For GPG-signed commits: the nonce is placed in a PGP armor Comment
# header, which does NOT invalidate the cryptographic signature but
# DOES affect the git SHA-1 hash. This allows mining and signing
# to coexist.
#
# For unsigned commits: the nonce is appended to the commit message.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Parse mode and arguments ──

MODE="zeros"
TARGET_ZEROS=7
TARGET_PREFIX=""

case "${1:-7}" in
	infinite)
		MODE="infinite"
		TARGET_ZEROS=0
		THREADS=${2:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}
		;;
	incremental)
		MODE="incremental"
		TARGET_ZEROS=0
		PREFIX_LENGTH=${2:-7}
		THREADS=${3:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}
		;;
	*)
		TARGET_ZEROS=${1:-7}
		THREADS=${2:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}
		;;
esac

NONCE_PLACEHOLDER="aaaaaaaaaa"
NONCE_LEN=${#NONCE_PLACEHOLDER}

# ── Auto-detect best available miner ──

IS_CUDA=0
if [ -x "$SCRIPT_DIR/gitminer" ]; then
	MINER="$SCRIPT_DIR/gitminer"
	IS_CUDA=1
	echo "Using CUDA GPU miner"
elif [ -x "$SCRIPT_DIR/gitminer_vulkan" ]; then
	MINER="$SCRIPT_DIR/gitminer_vulkan"
	echo "Using Vulkan GPU miner"
elif [ -x "$SCRIPT_DIR/gitminer_metal" ]; then
	MINER="$SCRIPT_DIR/gitminer_metal"
	echo "Using Metal GPU miner"
elif [ -x "$SCRIPT_DIR/gitminer_opencl" ]; then
	MINER="$SCRIPT_DIR/gitminer_opencl"
	echo "Using OpenCL GPU miner"
elif [ -x "$SCRIPT_DIR/gitminer_cpu" ]; then
	MINER="$SCRIPT_DIR/gitminer_cpu"
	echo "Using CPU miner"
else
	echo "Error: no miner found. Run 'make gitminer_metal', 'make gitminer_opencl', or 'make gitminer_cpu' first." >&2
	exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "Error: not inside a git repository." >&2
	exit 1
fi

COMMIT_HASH=$(git rev-parse HEAD)
echo "Mining commit: $COMMIT_HASH"

# ── For incremental mode, compute target prefix from commit number ──

if [ "$MODE" = "incremental" ]; then
	COMMIT_INDEX=$(( $(git rev-list --count HEAD) - 1 ))
	TARGET_PREFIX=$(printf "%0${PREFIX_LENGTH}x" "$COMMIT_INDEX")
	echo "Incremental mode: commit #$COMMIT_INDEX -> prefix $TARGET_PREFIX"
fi

# Check if commit is GPG-signed
IS_SIGNED=0
if git cat-file commit HEAD | grep -q '^gpgsig '; then
	IS_SIGNED=1
fi

if [ "$IS_SIGNED" = "1" ]; then
	echo "Commit is GPG-signed. Mining via PGP armor Comment nonce."

	# Inject Comment: nonce=aaaaaaaaaa into the gpgsig armor block.
	# This line is NOT part of the cryptographic signature (GPG ignores
	# armor headers during verification), but IS part of the git object hash.
	python3 -c "
import sys

content = open('.git/' + open('.git/HEAD').read().strip().split(': ')[1], 'rb').read() if False else None
# Read the raw commit content via git
import subprocess
raw = subprocess.check_output(['git', 'cat-file', 'commit', 'HEAD'])

lines = raw.split(b'\n')
result = []
nonce_line = b' Comment: nonce=${NONCE_PLACEHOLDER}'
found_gpgsig = False
comment_replaced = False

for line in lines:
    # Look for existing Comment: nonce= line and replace it
    if found_gpgsig and line.startswith(b' Comment: nonce='):
        result.append(nonce_line)
        comment_replaced = True
        continue
    result.append(line)
    if line.startswith(b'gpgsig -----BEGIN'):
        found_gpgsig = True
        if not comment_replaced:
            # Insert Comment line right after BEGIN line
            result.append(nonce_line)
            comment_replaced = True

if not comment_replaced:
    print('Error: could not find gpgsig block', file=sys.stderr)
    sys.exit(1)

modified = b'\n'.join(result)
# Build full git object
header = b'commit ' + str(len(modified)).encode() + b'\x00'
full_object = header + modified
open('base.txt', 'wb').write(full_object)

# Find nonce position
nonce_marker = b'nonce=${NONCE_PLACEHOLDER}'
pos = full_object.find(nonce_marker)
if pos == -1:
    print('Error: nonce not found in object', file=sys.stderr)
    sys.exit(1)
# The actual nonce starts after 'nonce='
nonce_pos = pos + len(b'nonce=')
print(nonce_pos)
"
	NONCE_POS=$?
	# Re-run to capture output (previous was exit code check)
	NONCE_POS=$(python3 -c "
import subprocess
raw = subprocess.check_output(['git', 'cat-file', 'commit', 'HEAD'])
lines = raw.split(b'\n')
result = []
nonce_line = b' Comment: nonce=${NONCE_PLACEHOLDER}'
found_gpgsig = False
comment_replaced = False
for line in lines:
    if found_gpgsig and line.startswith(b' Comment: nonce='):
        result.append(nonce_line)
        comment_replaced = True
        continue
    result.append(line)
    if line.startswith(b'gpgsig -----BEGIN'):
        found_gpgsig = True
        if not comment_replaced:
            result.append(nonce_line)
            comment_replaced = True
modified = b'\n'.join(result)
header = b'commit ' + str(len(modified)).encode() + b'\x00'
full_object = header + modified
open('base.txt', 'wb').write(full_object)
nonce_marker = b'nonce=${NONCE_PLACEHOLDER}'
pos = full_object.find(nonce_marker)
nonce_pos = pos + len(b'nonce=')
print(nonce_pos)
")

else
	echo "Commit is unsigned. Mining via message nonce."

	ORIG_MSG=$(git log -1 --format='%B')

	if echo "$ORIG_MSG" | grep -q '^nonce:'; then
		NEW_MSG=$(echo "$ORIG_MSG" | sed "s/^nonce:.*$/nonce:${NONCE_PLACEHOLDER}/")
	else
		NEW_MSG=$(printf '%s\nnonce:%s\n' "$(echo "$ORIG_MSG" | sed -e 's/[[:space:]]*$//')" "$NONCE_PLACEHOLDER")
	fi

	AUTHOR_DATE=$(git log -1 --format='%aI')
	COMMITTER_DATE=$(git log -1 --format='%cI')
	GIT_AUTHOR_DATE="$AUTHOR_DATE" GIT_COMMITTER_DATE="$COMMITTER_DATE" \
		git commit --amend -m "$NEW_MSG" --allow-empty >/dev/null 2>&1

	COMMIT_CONTENT=$(git cat-file commit HEAD)
	CONTENT_LEN=$(printf '%s' "$COMMIT_CONTENT" | wc -c | tr -d ' ')
	printf "commit %d\0%s" "$CONTENT_LEN" "$COMMIT_CONTENT" > base.txt

	NONCE_POS=$(python3 -c "
data = open('base.txt', 'rb').read()
pos = data.find(b'${NONCE_PLACEHOLDER}')
print(pos if pos != -1 else -1)
")
fi

if [ "$NONCE_POS" = "-1" ] || [ -z "$NONCE_POS" ]; then
	echo "Error: could not find nonce placeholder in commit object." >&2
	exit 1
fi

NONCE_END=$((NONCE_POS + NONCE_LEN))
echo "Nonce position: [$NONCE_POS, $NONCE_END)"

# ── Display target info ──

case "$MODE" in
	infinite)
		echo "Mode: infinite (finding lowest hash, Ctrl+C to stop)"
		;;
	incremental)
		echo "Mode: incremental (target prefix: $TARGET_PREFIX)"
		;;
	*)
		echo "Target: $TARGET_ZEROS leading hex zeros"
		;;
esac

echo "Threads: $THREADS"
echo "Mining..."

# ── Build miner arguments ──

MINER_ARGS=("$THREADS" /dev/stderr result.txt "$NONCE_POS" "$NONCE_END" "$TARGET_ZEROS")

if [ -n "$TARGET_PREFIX" ]; then
	if [ "$IS_CUDA" = "1" ]; then
		MINER_ARGS+=(1024 "$TARGET_PREFIX")
	else
		MINER_ARGS+=("$TARGET_PREFIX")
	fi
fi

# ── Run the miner ──

if [ "$MODE" = "infinite" ]; then
	# Run in background so we can trap Ctrl+C and apply best result
	"$MINER" "${MINER_ARGS[@]}" 2>&1 &
	MINER_PID=$!
	cleanup() {
		echo ""
		echo "Stopping miner (PID $MINER_PID)..."
		kill "$MINER_PID" 2>/dev/null || true
		wait "$MINER_PID" 2>/dev/null || true
	}
	trap cleanup INT TERM
	wait "$MINER_PID" 2>/dev/null || true
	trap - INT TERM
else
	"$MINER" "${MINER_ARGS[@]}" 2>&1
fi

# ── Process result ──

if [ ! -f result.txt ]; then
	if [ "$MODE" = "infinite" ]; then
		echo "No result found (miner was stopped before finding any hash)." >&2
		rm -f base.txt
		exit 1
	fi
	echo "Error: miner did not produce result.txt" >&2
	exit 1
fi

MINED_NONCE=$(dd if=result.txt bs=1 skip="$NONCE_POS" count="$NONCE_LEN" 2>/dev/null)
echo "Mined nonce: $MINED_NONCE"

# Extract commit content from result.txt (strip "commit <len>\0" header)
python3 -c "
data = open('result.txt', 'rb').read()
null_pos = data.index(b'\x00')
open('commit_content.tmp', 'wb').write(data[null_pos+1:])
"

NEW_HASH=$(git hash-object -t commit -w commit_content.tmp)
echo "New commit hash: $NEW_HASH"

ZEROS=$(python3 -c "h='$NEW_HASH'; print(len(h) - len(h.lstrip('0')))")
echo "Leading zeros: $ZEROS"

APPLY_RESULT=0

case "$MODE" in
	infinite)
		# Always apply in infinite mode (best result found)
		APPLY_RESULT=1
		echo "Best hash found during mining session."
		;;
	incremental)
		# Verify the prefix matches
		ACTUAL_PREFIX=$(python3 -c "print('$NEW_HASH'[:${PREFIX_LENGTH}])")
		if [ "$ACTUAL_PREFIX" = "$TARGET_PREFIX" ]; then
			APPLY_RESULT=1
		else
			echo "Warning: hash prefix '$ACTUAL_PREFIX' does not match target '$TARGET_PREFIX'" >&2
		fi
		;;
	*)
		if [ "$ZEROS" -ge "$TARGET_ZEROS" ]; then
			APPLY_RESULT=1
		else
			echo "Warning: hash only has $ZEROS leading zeros (target: $TARGET_ZEROS)" >&2
		fi
		;;
esac

if [ "$APPLY_RESULT" = "1" ]; then
	BRANCH=$(git branch --show-current)
	if [ -n "$BRANCH" ]; then
		git update-ref "refs/heads/$BRANCH" "$NEW_HASH"
		echo "Success! Branch '$BRANCH' now points to $NEW_HASH"
	else
		git update-ref HEAD "$NEW_HASH"
		echo "Success! HEAD now points to $NEW_HASH"
	fi

	# Verify signature if signed
	if [ "$IS_SIGNED" = "1" ]; then
		echo "Verifying GPG signature..."
		if git verify-commit "$NEW_HASH" 2>&1; then
			echo "GPG signature: VALID"
		else
			echo "WARNING: GPG signature verification failed!" >&2
		fi
	fi
fi

# Cleanup
rm -f base.txt result.txt commit_content.tmp log.txt

echo "Done! Final commit: $(git rev-parse HEAD)"
