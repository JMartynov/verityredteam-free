# M9: Dynamic, Narrow Terminal Screencast GIF (Charmbracelet VHS in Docker)

- **Task ID**: `M9`
- **Priority**: `P1`
- **Status**: `Todo`
- **Dependencies**: `M7`, `M8`
- **Blocks**: `M10`
- **Target Repository**: `/Users/ivan/Project/3t.tools.intellij/verityredteam-free` (`verity-redteam-core`)
- **GitHub Project #5**: [Verity RedTeam Free Task Board](https://github.com/users/JMartynov/projects/5)

---

## 1. Problem Statement & Audit Findings

The current hero visual in `README.md` (`docs/assets/demo.svg`, `59,979` bytes, `1285 × 1975.6 px`) has three major problems:
1. **It is completely static**: `demo.svg` is a single-frame Rich SVG export with zero CSS `@keyframes`, `<animate>`, or SMIL/GIF motion — it does not animate or transition across scenarios at all.
2. **It is oversized vertically**: At `1975.6 px` tall, it creates a huge wall-of-text image on GitHub instead of a compact, scannable screencast.
3. **It has a stale package command**: Line `289` of `docs/assets/demo.svg` displays `$ uvx --from verity-core verity scan`, whereas `pyproject.toml` uses package name `verity-redteam-core`.

Customers evaluating a CLI security tool on GitHub want a **crisp, narrow, genuinely dynamic terminal video/GIF** showing real commands being typed and real security findings appearing live.

---

## 2. Confirmed Technical Specification

- **Tooling**: **Charmbracelet VHS** (`docs/assets/demo.tape`) executed reproducibly inside a clean Docker recording container (`ghcr.io/charmbracelet/vhs` or custom recording image with `vhs`, `ttyd`, `ffmpeg`, `gifsicle`, Python 3.12, freshly installed `verity-redteam-core`, and `M8` demo fixtures).
- **Dimensions & Visual Constraints (Narrow & Above-the-Fold)**:
  - `Set Width 860` (hard limit: `<= 900 px`)
  - `Set Height 440` (hard limit: `<= 480 px`)
  - `Set FontSize 14`, `Set Padding 16`, `Set WindowBar Colorful` (~88–92 cols × ~22 rows so Rich tables never wrap awkwardly)
  - `Set Framerate 18` (between `15` and `20`), `Set TypingSpeed 40ms`, infinite loop (`LoopOffset` / default loop)
  - Post-optimization via `gifsicle -O3 --lossy=30 --colors 128` targeting **< 2.5 MB** (`< 1.5 MB` preferred) for fast loading on GitHub README.
- **No Fake Hardcoded Output**: Every frame must be recorded from **live executions** of `verity` against real/fixture vulnerable targets (from `M8`) inside the recording container.

---

## 3. Dynamic 4-Scene Storyboard (~24 Seconds Total)

| Scene | Time | Command Typed Live | What Appears Dynamically on Screen |
| :--- | :--- | :--- | :--- |
| **1. Workstation Secret & Config Audit** | `0–6s` | `verity scan --config-file ~/.cursor/mcp.json` | Live Rich summary & findings table showing plaintext secret caught and scrubbed (`KEY=****`), unsafe `bash -c` wrapper flagged, and poisoned schema detected (`CRITICAL`/`HIGH`). |
| **2. Live Poisoned MCP Probe** | `6–12s` | `verity test --command "python vuln_mcp.py"` | Clear transition, live `stdio` probe output streaming `FAIL` rows for Prompt Injection Override (`CWE-74`), Tool Poisoning (`CWE-358`), and Exfil Webhook (`CWE-200`). |
| **3. Deterministic SQL AST Guard** | `12–18s` | `verity test --sql "SELECT id FROM users; DROP TABLE users;--"` followed by `verity test --sql "SELECT id, email FROM orders WHERE tenant_id = :tenant_id"` | Immediate red `FAIL` blocking stacked SQL injection (`TokenType.SEMICOLON`), followed by green `PASS` on safe parameterized `SELECT`. |
| **4. 4-Target Demo & Python AST Gate** | `18–24s` | `verity test --demo` and `verity scan --path ./vuln_mcp.py --fail-on-findings` | Shows 4/4 `PASS` zero-Docker checks (`SQLite`, `Postgres`, `Mongo`, `Code Exec`) and AST scan flagging `eval()` (`CWE-94`) + `shell=True` (`CWE-78`) with `exit 1`. |

*(Note: Keep prompt concise e.g. `$ ` instead of long container paths, and `Clear` between scenes so every scene fits cleanly inside `860 × 440` without clipped tables.)*

---

## 4. Deliverables

1. `docs/assets/demo.tape` — Declarative VHS script defining narrow geometry, theme, typing cadence, and all 4 live scenes.
2. `scripts/record_demo_gif.sh` (plus small recording Dockerfile if needed under `tests/e2e_containers/` or `scripts/`) — One-command reproducible container recorder that installs `verity-redteam-core` wheel + `M8` fixtures, runs `vhs docs/assets/demo.tape`, optimizes with `gifsicle`, and validates GIF properties.
3. `docs/assets/demo.gif` — Final optimized narrow animated GIF replacing `docs/assets/demo.svg` in `README.md` (and verify whether `docs/assets/demo.svg` should be removed once `M10` switches `README.md`).

---

## 5. Verification Commands

Record and validate the GIF:
```bash
cd /Users/ivan/Project/3t.tools.intellij/verityredteam-free
./scripts/record_demo_gif.sh
python3 - <<'PY'
from pathlib import Path
from PIL import Image

gif = Path("docs/assets/demo.gif")
assert gif.is_file(), "demo.gif missing"
size_mb = gif.stat().st_size / (1024 * 1024)
with Image.open(gif) as im:
    print(f"size={size_mb:.2f}MB dims={im.size} animated={getattr(im, 'is_animated', False)} frames={getattr(im, 'n_frames', 1)}")
    assert getattr(im, "is_animated", False) is True
    assert getattr(im, "n_frames", 1) >= 100
    assert im.size[0] <= 900 and im.size[1] <= 480
    assert size_mb < 2.5
PY
```

---

## 6. Acceptance Criteria

- [ ] `docs/assets/demo.gif` is a genuinely animated multi-frame GIF (`is_animated == True`, `n_frames >= 100`, smooth typing + scene transitions across all 4 scenes).
- [ ] Geometry is narrow and crisp (`width <= 900 px`, `height <= 480 px`, targeting `860 × 440 px`) with zero wrapped/broken Rich table borders.
- [ ] File size is `< 2.5 MB` after `gifsicle` optimization.
- [ ] All commands shown in the GIF use valid `verity` / `verity-redteam-core` syntax (zero stale `verity-core` references) and record live output from real CLI execution.
- [ ] `./scripts/record_demo_gif.sh` cleanly regenerates `docs/assets/demo.gif` from `docs/assets/demo.tape` inside Docker with zero host dependencies beyond Docker.

---

## 7. Out of Scope

- Updating `README.md` text and structure (handled in `M10`).
- Adding static SVG fallbacks or non-terminal marketing graphics.
