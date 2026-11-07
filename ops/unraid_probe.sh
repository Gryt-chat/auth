#!/bin/bash
# Runs on Unraid every minute (GRYT-2038). Checks auth from the internet side, so it catches the VPS, the
# tunnel and DNS. After five failed runs in a row it hands alertmanager an alert that lapses after five minutes.
set -uo pipefail

AM="${AM:-http://127.0.0.1:19093}"
STATE="${STATE:-/tmp/gryt-auth-probe.failures}"

down=()
curl -fsS -m 10 -o /dev/null https://auth.gryt.chat/realms/gryt/.well-known/openid-configuration || down+=(auth.gryt.chat)
curl -fsS -m 10 https://id.gryt.chat/health 2>/dev/null | grep -q '"ok"' || down+=(id.gryt.chat)

if [[ ${#down[@]} -eq 0 ]]; then
  rm -f "$STATE"
  exit 0
fi

n=$(( $(cat "$STATE" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STATE"
echo "down (run $n): ${down[*]}" >&2
(( n >= 5 )) || exit 1  # the home router restarts at night

ends="$(date -u -d '+5 min' +%FT%TZ)"
for host in "${down[@]}"; do
  curl -fsS -m 5 -X POST -H 'Content-Type: application/json' "$AM/api/v2/alerts" -d "[{
    \"labels\": {\"alertname\": \"AuthUnreachableFromOutside\", \"instance\": \"$host\", \"severity\": \"critical\"},
    \"annotations\": {\"summary\": \"$host hasn't answered Unraid for $n minutes\"},
    \"endsAt\": \"$ends\"}]" || echo "alertmanager refused the alert" >&2
done
exit 1
