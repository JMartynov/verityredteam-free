#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.verify.yml"
BUILD_DIST="$SCRIPT_DIR/.build_dist"
INSTALL_SOURCE="${INSTALL_SOURCE:-wheel}"

cleanup() {
  docker compose -f "$COMPOSE_FILE" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$BUILD_DIST"
}
trap cleanup EXIT

cd "$REPO_ROOT"

rm -rf "$BUILD_DIST"
mkdir -p "$BUILD_DIST" "$SCRIPT_DIR/snapshots"

uv build

shopt -s nullglob
wheels=("$REPO_ROOT"/dist/verity_redteam_core-*.whl)
shopt -u nullglob

if [ "${#wheels[@]}" -eq 0 ]; then
  echo "uv build did not produce a verity_redteam_core wheel" >&2
  exit 1
fi

cp "${wheels[0]}" "$BUILD_DIST/"
echo "Staged wheel: ${wheels[0]}"

docker compose -f "$COMPOSE_FILE" build --no-cache \
  --build-arg INSTALL_SOURCE="$INSTALL_SOURCE"

docker compose -f "$COMPOSE_FILE" up -d --wait target-sse-lab

overall=0
run_customer() {
  local service="$1"
  if docker compose -f "$COMPOSE_FILE" run --rm "$service"; then
    echo "customer container passed: $service"
  else
    echo "customer container FAILED: $service" >&2
    overall=1
  fi
}

run_customer customer-pip
run_customer customer-uvx
run_customer customer-full-workstation

if [ "$overall" -ne 0 ]; then
  echo "One or more customer containers failed" >&2
  exit 1
fi

echo "All customer containers passed"
