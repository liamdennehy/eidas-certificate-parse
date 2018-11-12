#!/bin/sh
[ -d tests ] && export tests=tests/ || export tests=../tests

echo
echo phpunit tests included:
echo
for f in $tests/*.php; do
  basename "$f"
  for t in $(grep 'function test' "$f" | cut -d' ' -f7); do
    echo "  $t"
    done
  done
