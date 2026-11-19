#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="verity-demo-recorder:local"
GIF="$REPO_ROOT/docs/assets/demo.gif"
RAW_GIF="$REPO_ROOT/docs/assets/demo_raw.gif"
STAGE="$(mktemp -d)"

cleanup() {
  rm -rf "$STAGE"
  rm -f "$RAW_GIF"
}
trap cleanup EXIT

cd "$REPO_ROOT"

echo "==> Building wheel"
uv build

rm -rf "$STAGE/.build_dist"
mkdir -p "$STAGE/.build_dist"
cp dist/verity_redteam_core-*.whl "$STAGE/.build_dist/"
cp tests/e2e_containers/fixtures/vuln_stdio_mcp.py "$STAGE/"
cp tests/e2e_containers/fixtures/ast_vuln_server.py "$STAGE/"
cp scripts/Dockerfile.demo-recorder "$STAGE/"

echo "==> Building recorder image"
docker build -f "$STAGE/Dockerfile.demo-recorder" -t "$IMAGE" "$STAGE"

echo "==> Recording screencast"
docker run --rm --entrypoint bash \
  -v "$REPO_ROOT/docs/assets:/out" \
  -v "$REPO_ROOT/docs/assets/demo.tape:/demo/demo.tape:ro" \
  "$IMAGE" -lc \
  "vhs /demo/demo.tape && gifsicle -O3 --lossy=30 --colors 128 /out/demo_raw.gif -o /out/demo.gif && rm -f /out/demo_raw.gif"

if [ ! -f "$GIF" ]; then
  echo "error: $GIF was not produced" >&2
  exit 1
fi

SIZE="$(wc -c < "$GIF" | tr -d ' ')"
if [ "$SIZE" -ge 2621440 ]; then
  echo "==> $SIZE bytes exceeds 2.5MB, re-optimizing aggressively"
  docker run --rm --entrypoint bash \
    -v "$REPO_ROOT/docs/assets:/out" \
    "$IMAGE" -lc \
    "gifsicle -O3 --lossy=60 --colors 96 /out/demo.gif -o /out/demo_opt.gif && mv /out/demo_opt.gif /out/demo.gif"
fi

echo "==> Validating $GIF"
uv run --with pillow python3 - "$GIF" <<'PY'
import sys
from pathlib import Path

from PIL import Image

gif = Path(sys.argv[1])
size_mb = gif.stat().st_size / (1024 * 1024)
with Image.open(gif) as im:
    width, height = im.size
    frames = getattr(im, "n_frames", 1)
    animated = bool(getattr(im, "is_animated", False))

print(f"{gif}: {width}x{height}px, {frames} frames, animated={animated}, {size_mb:.2f}MB")

assert animated is True, "demo.gif is not animated"
assert frames >= 100, f"expected >= 100 frames, got {frames}"
assert width <= 900 and height <= 480, f"geometry {width}x{height} exceeds 900x480"
assert size_mb < 2.5, f"{size_mb:.2f}MB exceeds 2.5MB"
PY

echo "==> Done: $GIF"
