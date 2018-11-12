#!/bin/sh
mydir=$(dirname ${BASH_SOURCE[0]})

echo
echo phpunit tests included:
echo
for f in $mydir/../tests/*.php; do
  basename "$f"
  for t in $(grep 'function test' "$f" | cut -d' ' -f7); do
    echo "  $t"
    done
  done
