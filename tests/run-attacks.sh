#!/bin/sh
# Runs the outside-attacker test suite against a local copy of the server code.
# Usage: sh tests/run-attacks.sh   (needs Node 22+)
cd "$(dirname "$0")"
sed -e 's#^import type .*##' -e 's#"@netlify/blobs"#"./fake-blobs.mjs"#' ../netlify/functions/notes.mts > .fn-under-test.mts
out=$(node --experimental-strip-types attack.mts 2>&1 | grep -v ExperimentalWarning)
status=$?
rm -f .fn-under-test.mts
echo "$out"
passed=$(echo "$out" | grep -c "✔")
failed=$(echo "$out" | grep -c "✘")
echo "----"
if [ "$passed" -eq 0 ]; then echo "SUITE DID NOT RUN"; exit 1; fi
echo "$passed passed, $failed failed"
[ "$failed" -eq 0 ]
