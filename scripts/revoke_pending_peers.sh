#!/usr/bin/env bash
set -euo pipefail

DB_CONTAINER="vpnztna-postgres-1"
WG_INTERFACE="${WG_INTERFACE:-wg0}"

SQL="COPY (
  SELECT id, public_key
  FROM peers
  WHERE provisioning_status = 'pending_revoke'
    AND public_key IS NOT NULL
  ORDER BY id
) TO STDOUT WITH CSV"

rows="$(docker exec -i "$DB_CONTAINER" psql -U vpnztna -d vpnztna -At -F',' -c "$SQL")"

if [ -z "${rows}" ]; then
  exit 0
fi

while IFS=, read -r peer_id public_key; do
  [ -z "${peer_id:-}" ] && continue

  if wg set "$WG_INTERFACE" peer "$public_key" remove; then
    docker exec -i "$DB_CONTAINER" psql -U vpnztna -d vpnztna -c "
      UPDATE peers
      SET provisioning_status = 'removed',
          provisioning_error = NULL,
          updated_at = NOW()
      WHERE id = ${peer_id};
    " >/dev/null
  else
    docker exec -i "$DB_CONTAINER" psql -U vpnztna -d vpnztna -c "
      UPDATE peers
      SET provisioning_status = 'error',
          provisioning_error = 'Provisioning agent failed to revoke peer from WireGuard runtime',
          updated_at = NOW()
      WHERE id = ${peer_id};
    " >/dev/null
  fi
done <<< "$rows"
