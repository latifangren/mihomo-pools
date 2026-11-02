#!/bin/sh
# Measure the egress country of each pinned port, then rename from results.
# Do not trust catalog remarks as country labels.

echo "== pin-01 :10101 =="
curl -s -x http://127.0.0.1:10101 https://ipwho.is/ ; echo
echo "== pin-02 :10102 =="
curl -s -x http://127.0.0.1:10102 https://ipwho.is/ ; echo
