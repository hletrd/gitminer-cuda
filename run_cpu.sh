#!/bin/bash
THREADS=${1:-$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)}
./gitminer_cpu "$THREADS" log.txt result.txt
