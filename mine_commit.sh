#!/bin/bash
#
# mine_commit.sh - Mine a git commit hash with leading zeros
#
# Usage: mine_commit.sh [target_zeros] [threads]
#   target_zeros: number of leading hex zeros (default: 7)
#   threads:      CPU threads to use (default: auto-detect)
#
# Must be run from within a git repository after making a commit.
# The most recent commit will be re-created with a nonce that produces
# a hash with the desired number of leading zeros.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MINER="$SCRIPT_DIR/gitminer_cpu"

TARGET_ZEROS=${1:-7}
THREADS=${2:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}

NONCE_PLACEHOLDER="aaaaaaaaaa"
NONCE_LEN=${#NONCE_PLACEHOLDER}

if [ ! -x "$MINER" ]; then
	echo "Error: gitminer_cpu not found. Run 'make gitminer_cpu' first." >&2
	exit 1
fi

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
	echo "Error: not inside a git repository." >&2
	exit 1
fi

# Get current commit info
COMMIT_HASH=$(git rev-parse HEAD)
echo "Mining commit: $COMMIT_HASH"

# Get the original commit message
ORIG_MSG=$(git log -1 --format='%B')

# Check if message already has a nonce line
if echo "$ORIG_MSG" | grep -q '^nonce:'; then
	# Replace existing nonce
	NEW_MSG=$(echo "$ORIG_MSG" | sed "s/^nonce:.*$/nonce:${NONCE_PLACEHOLDER}/")
else
	# Append nonce line
	# Remove trailing newlines from original message, then add nonce
	NEW_MSG=$(printf '%s\nnonce:%s\n' "$(echo "$ORIG_MSG" | sed -e 's/[[:space:]]*$//')" "$NONCE_PLACEHOLDER")
fi

# Amend commit with nonce placeholder, preserving timestamps
AUTHOR_DATE=$(git log -1 --format='%aI')
COMMITTER_DATE=$(git log -1 --format='%cI')
GIT_AUTHOR_DATE="$AUTHOR_DATE" GIT_COMMITTER_DATE="$COMMITTER_DATE" \
	git commit --amend -m "$NEW_MSG" --no-edit --allow-empty --date="$AUTHOR_DATE" >/dev/null 2>&1 || \
	GIT_AUTHOR_DATE="$AUTHOR_DATE" GIT_COMMITTER_DATE="$COMMITTER_DATE" \
	git commit --amend -m "$NEW_MSG" --allow-empty >/dev/null 2>&1

# Get the raw commit object content
COMMIT_CONTENT=$(git cat-file commit HEAD)
CONTENT_LEN=$(echo -n "$COMMIT_CONTENT" | wc -c | tr -d ' ')

# Build the full git object (header + content) as base.txt
printf "commit %d\0%s" "$CONTENT_LEN" "$COMMIT_CONTENT" > base.txt

# Find the nonce position in base.txt
NONCE_POS=$(python3 -c "
data = open('base.txt', 'rb').read()
pos = data.find(b'${NONCE_PLACEHOLDER}')
if pos == -1:
    print(-1)
else:
    print(pos)
")

if [ "$NONCE_POS" = "-1" ]; then
	echo "Error: could not find nonce placeholder in commit object." >&2
	exit 1
fi

NONCE_END=$((NONCE_POS + NONCE_LEN))
echo "Nonce position: [$NONCE_POS, $NONCE_END)"
echo "Target: $TARGET_ZEROS leading hex zeros"
echo "Threads: $THREADS"
echo "Mining..."

# Run the miner
"$MINER" "$THREADS" /dev/stderr result.txt "$NONCE_POS" "$NONCE_END" "$TARGET_ZEROS" 2>&1

# Verify result
if [ ! -f result.txt ]; then
	echo "Error: miner did not produce result.txt" >&2
	exit 1
fi

# Extract the mined nonce from result.txt
MINED_NONCE=$(dd if=result.txt bs=1 skip="$NONCE_POS" count="$NONCE_LEN" 2>/dev/null)
echo "Mined nonce: $MINED_NONCE"

# Extract commit content from result.txt (strip the "commit <len>\0" header)
python3 -c "
data = open('result.txt', 'rb').read()
null_pos = data.index(b'\x00')
open('commit_content.tmp', 'wb').write(data[null_pos+1:])
"

# Import the mined commit object into git
NEW_HASH=$(git hash-object -t commit -w commit_content.tmp)
echo "New commit hash: $NEW_HASH"

# Count leading zeros
ZEROS=$(python3 -c "h='$NEW_HASH'; print(len(h) - len(h.lstrip('0')))")
echo "Leading zeros: $ZEROS"

if [ "$ZEROS" -ge "$TARGET_ZEROS" ]; then
	# Update the branch ref to point to the new commit
	BRANCH=$(git branch --show-current)
	if [ -n "$BRANCH" ]; then
		git update-ref "refs/heads/$BRANCH" "$NEW_HASH"
		echo "Success! Branch '$BRANCH' now points to $NEW_HASH"
	else
		# Detached HEAD
		git update-ref HEAD "$NEW_HASH"
		echo "Success! HEAD now points to $NEW_HASH"
	fi
else
	echo "Warning: hash only has $ZEROS leading zeros (target: $TARGET_ZEROS)" >&2
fi

# Cleanup
rm -f base.txt result.txt commit_content.tmp log.txt

echo "Done! Final commit: $(git rev-parse HEAD)"
