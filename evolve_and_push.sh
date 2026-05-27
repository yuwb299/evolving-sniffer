#!/bin/bash
# evolve_and_push.sh - Run one evolution iteration and push to GitHub
set -e
cd "$(dirname "$0")"

# Ensure target dir exists
mkdir -p target memory

# Run evolution
python3 -m agent.core 2>&1 | tee -a memory/cron.log

echo ""
echo "=== Evolution run complete ==="
