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
# For GPG-signed commits: the nonce is placed in a PGP armor Comment
# header, which does NOT invalidate the cryptographic signature but
# DOES affect the git SHA-1 hash. This allows mining and signing
# to coexist.
#
# For unsigned commits: the nonce is appended to the commit message.
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

COMMIT_HASH=$(git rev-parse HEAD)
echo "Mining commit: $COMMIT_HASH"

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
echo "Target: $TARGET_ZEROS leading hex zeros"
echo "Threads: $THREADS"
echo "Mining..."

# Run the miner
"$MINER" "$THREADS" /dev/stderr result.txt "$NONCE_POS" "$NONCE_END" "$TARGET_ZEROS" 2>&1

if [ ! -f result.txt ]; then
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

if [ "$ZEROS" -ge "$TARGET_ZEROS" ]; then
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
else
	echo "Warning: hash only has $ZEROS leading zeros (target: $TARGET_ZEROS)" >&2
fi

# Cleanup
rm -f base.txt result.txt commit_content.tmp log.txt

echo "Done! Final commit: $(git rev-parse HEAD)"
