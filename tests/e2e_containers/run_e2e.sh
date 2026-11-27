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

if [ -z "${VERITY_VERSION:-}" ]; then
  if [ -f "$REPO_ROOT/pyproject.toml" ]; then
    VERITY_VERSION="$(python3 -c 'import tomllib;print(tomllib.load(open("pyproject.toml","rb"))["project"]["version"])')"
  else
    VERITY_VERSION="0.0.0"
  fi
fi
export VERITY_VERSION

rm -rf "$BUILD_DIST"
mkdir -p "$BUILD_DIST" "$SCRIPT_DIR/snapshots"

if [ -f "$REPO_ROOT/README.md" ]; then
  mkdir -p "$BUILD_DIST/docs/.github/workflows" "$BUILD_DIST/docs/docs"
  for doc_rel in README.md LICENSE .github/workflows/ci.yml AGENTS.md docs/extensibility.md TASK_BOARD.md; do
    if [ -f "$REPO_ROOT/$doc_rel" ]; then
      cp "$REPO_ROOT/$doc_rel" "$BUILD_DIST/docs/$doc_rel"
    fi
  done
fi

if [ "$INSTALL_SOURCE" = "wheel" ]; then
  rm -f "$REPO_ROOT"/dist/verity_redteam_core-*.whl
  rm -f "$BUILD_DIST"/verity_redteam_core-*.whl

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
fi

docker compose -f "$COMPOSE_FILE" build --no-cache \
  --build-arg INSTALL_SOURCE="$INSTALL_SOURCE" \
  --build-arg VERITY_VERSION="$VERITY_VERSION"

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

run_airgapped() {
  local image="${AIRGAP_IMAGE:-verity-e2e-customer-pip}"
  docker run --rm --network none \
    -e VERITY_CACHE_DIR=/tmp/cold_cache \
    "$image" bash -lc '
set -e
mkdir -p /tmp/cold_cache
cat > /tmp/airgap_mcp.json <<"JSON"
{"mcpServers":{"leaky-workstation":{"command":"bash","args":["-c","npx -y mcp-remote@0.1.15"],"env":{"OPENAI_API_KEY":"sk-live-airgapped-secret-1234567890"}},"remote":{"command":"npx","args":["-y","mcp-remote@0.1.15"]}}}
JSON
start=$(date +%s%N)
set +e
verity scan --config-file /tmp/airgap_mcp.json --offline --format json --fail-on-findings > /tmp/scan_out.json 2> /tmp/scan_err.txt
scan_rc=$?
set -e
end=$(date +%s%N)
elapsed_ms=$(( (end - start) / 1000000 ))
echo "air-gapped scan rc=$scan_rc elapsed_ms=$elapsed_ms"
cat /tmp/scan_err.txt
cat /tmp/scan_out.json
[ "$scan_rc" -eq 1 ] || { echo "expected exit 1 from air-gapped scan"; exit 1; }
[ "$elapsed_ms" -lt 3000 ] || { echo "air-gapped scan exceeded 3s"; exit 1; }
grep -q "SEC-STATIC-SECRET-IN-CONFIG" /tmp/scan_out.json
grep -q "SEC-STATIC-UNSAFE-SHELL-WRAPPER" /tmp/scan_out.json
grep -q "VULN-CVE-2025-6514" /tmp/scan_out.json
if grep -q "Traceback" /tmp/scan_err.txt; then
  echo "air-gapped scan emitted a traceback"; exit 1
fi
if grep -q "sk-live-airgapped-secret-1234567890" /tmp/scan_out.json; then
  echo "air-gapped scan leaked plaintext secret"; exit 1
fi
set +e
verity test --command "python3 /opt/fixtures/vuln_stdio_mcp.py" > /tmp/probe_out.txt 2>&1
probe_rc=$?
set -e
cat /tmp/probe_out.txt
[ "$probe_rc" -eq 1 ] || { echo "expected exit 1 from stdio probe"; exit 1; }
for rule in VERITY-STATIC-INJECTION-OVERRIDE VERITY-STATIC-TOOL-POISONING VERITY-STATIC-EXFIL-WEBHOOK VERITY-STATIC-METADATA-SSRF; do
  grep -q "$rule" /tmp/probe_out.txt || { echo "missing probe rule $rule"; exit 1; }
done
'
}

if run_airgapped; then
  echo "air-gapped container passed"
else
  echo "air-gapped container FAILED" >&2
  overall=1
fi

if [ "$overall" -ne 0 ]; then
  echo "One or more customer containers failed" >&2
  exit 1
fi

echo "All customer containers passed"
