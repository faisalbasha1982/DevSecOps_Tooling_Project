#!/usr/bin/env bash
for s in CRITICAL HIGH MEDIUM LOW INFO medium "" SEVERE; do
  MIN_SEVERITY=$s ./run.sh sast >/tmp/o 2>&1; rc=$?
  echo "MIN_SEVERITY='$s' -> exit $rc  $(grep -oE 'blocking=[0-9]+|ERROR.*' /tmp/o | head -1 | cut -c1-60)"
done
