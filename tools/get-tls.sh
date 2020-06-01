#!/bin/bash

mkdir -p data/tl
echo Checking TL cache

if [ ! -f data/tl/lastupdate ]; then
  lastupdate=0
else
  lastupdate=$(cat data/tl/lastupdate)
  fi
now=$(date +%s)

age=$(($now - $lastupdate))
[ $age -lt 604800 ] && echo Less than one week since last update, skipping && exit 0

echo More than a week since last run, fetching new TLs
echo

php ./tools/get-tl-urls.php | jq -c '.[]' | while read line; do
  name="$(echo $line | jq .name -r)";
  filename=$(echo $line | jq .filename -r);
  echo $name;
  curl "$(echo $line | jq -r .url)" -A 'eIDAS PHP Certificate Library' > data/tl/$filename;
  done

date +%s > data/tl/lastupdate
