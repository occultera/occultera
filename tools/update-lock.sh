#!/bin/sh
# Regenerate requirements.lock (pinned versions + hashes for every platform) from requirements.txt.
# Needs uv (https://docs.astral.sh/uv/): pip install uv
set -eu
cd "$(dirname "$0")/.."
uv pip compile requirements.txt --python-version 3.15 --universal --generate-hashes --no-header -o requirements.lock
echo "requirements.lock updated — run the tests, then commit both files."
