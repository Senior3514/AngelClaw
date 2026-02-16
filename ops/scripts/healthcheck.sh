#!/usr/bin/env bash
# AngelGrid Health Watchdog
# Called by systemd timer every 2 minutes.
# If a container is down, restart the stack automatically.

set -euo pipefail

COMPOSE_DIR="/root/AngelGrid/ops"
LOG_TAG="angelgrid-watchdog"

log() { logger -t "$LOG_TAG" "$1"; echo "$1"; }

cd "$COMPOSE_DIR"

# Check each critical container
RESTART_NEEDED=false

for svc in cloud angelnode; do
  state=$(docker-compose ps -q "$svc" 2>/dev/null | xargs -r docker inspect -f '{{.State.Running}}' 2>/dev/null || echo "false")
  if [ "$state" != "true" ]; then
    log "WARNING: $svc is not running — will restart stack"
    RESTART_NEEDED=true
  fi
done

# HTTP health probes (only if containers appear running)
if [ "$RESTART_NEEDED" = "false" ]; then
  if ! curl -sf --max-time 5 http://127.0.0.1:8400/health > /dev/null 2>&1; then
    log "WARNING: ANGELNODE health probe failed"
    RESTART_NEEDED=true
  fi
  if ! curl -sf --max-time 5 http://127.0.0.1:8500/health > /dev/null 2>&1; then
    log "WARNING: Cloud API health probe failed"
    RESTART_NEEDED=true
  fi
fi

if [ "$RESTART_NEEDED" = "true" ]; then
  log "Restarting AngelGrid stack..."
  docker-compose up -d 2>&1 | while read -r line; do log "$line"; done
  sleep 8

  # Verify after restart
  OK=true
  curl -sf --max-time 5 http://127.0.0.1:8400/health > /dev/null 2>&1 || OK=false
  curl -sf --max-time 5 http://127.0.0.1:8500/health > /dev/null 2>&1 || OK=false

  if [ "$OK" = "true" ]; then
    log "Stack restarted successfully — all services healthy"
  else
    log "ERROR: Stack restart completed but health checks still failing"
    exit 1
  fi
else
  log "OK: all services healthy"
fi
