# Code-2-TXT

**Turn a whole codebase — or one script and everything it references — into a single, clean text file.**

Point it at a folder (or a main script), and Code-2-TXT walks through your project and
stitches every text and code file into one structured `.txt`, with clear file boundaries
and a manifest. It's built for **feeding code to an LLM, code review, auditing, archiving,
and documentation** — and it automatically leaves out the junk: binaries, firmware images,
build artifacts, and anything your `.gitignore` excludes.

It's a **single Python file**, GUI-only. No command line, no arguments, no setup. Run it,
click through two dialogs, done.

> **📷 Screenshot goes here** — paste your options-dialog image in the GitHub editor, which will replace this line with the image link.

<!-- Replace the line above with your screenshot, e.g. ![Options dialog](docs/options-dialog.png) -->


---

## Quick start

1. Make sure you have **Python 3.13.12**. This is the exact version the project is built and tested against — releases standardize on it and no other version is supported.
2. Run it:
   ```bash
   python Code-2-TXT.py
   ```
   (On Windows you can also build a standalone `.exe` — see [Building the .exe](#building-the-exe-windows).)
3. The options window opens. Pick a mode, leave the defaults or tweak them, press **OK**.
4. Choose the folder (or main file), then choose where to save the output.

That's it — you get a single combined `.txt` (or a set of numbered parts if you keep
splitting on).

---

## What it does

Code-2-TXT has two modes, and you pick one in the opening window.

### Folder mode (default)

Point it at a **root folder** and it recursively combines **every text-like file** under
it into one output. By default it respects your `.gitignore`, skips build/VCS/virtualenv
folders, and refuses anything that looks binary or like firmware.

Great for:
- Snapshotting a whole codebase to hand to an AI
- Config and documentation audits
- Archiving or reviewing a project

### Main-file mode (dependency-aware)

Point it at a **single script** (`.py`, `.ps1`, `.atsb`, `.vb`, `.bat`, …). It puts that
file first, then scans it for referenced files (`include`, `source`, `Import-Module`,
quoted paths, etc.), resolves them, and appends them — following references outward with
sensible safety limits.

Great for:
- Script bundles and automation frameworks
- Projects with helper files scattered around
- Sending a self-contained, runnable context to an LLM

---

## Using the options window

Everything is set in one window before anything runs:

- **Mode** — *Folder mode* (default) or *Main-file mode*. Each is explained right in the
  window.
- **Split output into multiple parts** *(on by default)* — when on, the output is split
  near a target line count. Set **Lines per part** with the spinbox (default 5000, max
  100000). Splits land on file boundaries; a single file bigger than the limit is split
  with clear continuation markers so the pieces are never mistaken for separate files.
  Turn it off to get one big file instead.
- **Respect .gitignore (folder mode)** *(on by default)* — when on, folder mode skips
  anything your `.gitignore` would exclude. Turn it off to ignore `.gitignore` entirely.
  (Disabled in main-file mode.)

Keyboard: **Enter = OK**, **Escape = Cancel**.

On Windows, folder mode opens the **classic folder-tree picker** (a plain expandable
tree where clicking a folder selects it) rather than the modern Explorer-style dialog.
On other platforms it uses the standard directory dialog.

---

## Output format

Each file is wrapped in a structured block:

```
===== FILE START =====
Path: relative/path/to/file
Absolute: C:\full\path\to\file
Size: 1234 bytes
Encoding: utf-8
----- BEGIN CONTENT -----
(file contents)
----- END CONTENT -----
===== FILE END =====
```

At the end, a **manifest** lists every included file in order. In folder mode, the header
also records whether `.gitignore` was honored.

### Split output (when enabled)

When splitting is on and the content exceeds the line target, output is written as
numbered parts: `name.part01of03.txt`, `name.part02of03.txt`, and so on.

- Parts split on file boundaries where possible.
- A single file larger than the threshold is split across parts on line boundaries. Its
  pieces use `===== FILE START (CONTINUED) =====`, a `SEGMENT n of m` banner, and
  `===== FILE SEGMENT END (MORE IN NEXT PART) =====` so they read as one continued file.
  Reassembling the segments in order reproduces the original exactly.
- Each part ends with a summary footer listing its entries and the full layout across all
  parts, so a tool reading any single part understands the chunking.

---

## Building the .exe (Windows)

A `BUILD_EXE.bat` is included to produce a standalone `dist\Code-2-TXT.exe`.

**Requirements**
- **Python 3.13.12 specifically.** `BUILD_EXE.bat` checks the running Python against this
  exact version and refuses to build on anything else, printing the download link and
  stopping. This is deliberate: every machine that builds a release uses the same
  interpreter, so builds stay reproducible.
- Build dependencies are pinned to exact versions in `requirements.txt` (PyInstaller +
  hooks-contrib) for the same reason. The app itself has **no runtime dependencies**
  beyond the Python standard library.

**Steps**
1. Install Python 3.13.12 (tick "Add python.exe to PATH" during install).
2. Double-click `BUILD_EXE.bat` (or run it from a terminal).
3. When it finishes, the executable is at `dist\Code-2-TXT.exe`.

The build reads the version from `version.txt` (a single line like `1.0.0`) and embeds it
as the Windows file version, visible under **Properties > Details** on the built `.exe`.
To change it, edit `version.txt` and rebuild.

---

## Technical reference

### .gitignore support (folder mode)

With **Respect .gitignore** on, folder mode matches Git's own decisions about what to
leave out. It's implemented with the **standard library only** (no extra dependencies) and
supports:

- Comments and blank lines
- Negation (`!pattern`)
- Directory-only patterns (trailing `/`) and everything beneath them
- Anchoring (a leading `/`, or any pattern containing a slash, is anchored to the
  `.gitignore`'s own location)
- `**` across path segments, plus single-level `*`, `?`, and `[...]` that don't cross `/`
- **Nested** `.gitignore` files, applied relative to the directory that contains them
- Last-match-wins precedence

Ignored directories are pruned before the tool recurses into them, and `.git/` is always
excluded.

### Supported text types

**Scripts & code** — Python, PowerShell, Batch, Shell, VB/VBA, C/C++/C#, Java, Go, Rust,
Swift, JavaScript/TypeScript, SQL.
**Config & data** — JSON, YAML, TOML, INI/CFG/CONF, CSV/TSV, `.env`.
**Docs & build** — `.txt`, `.md`, `.rst`, `.log`, `Makefile`, `Dockerfile`, `README`,
`LICENSE`, `pyproject.toml`, `package.json`.

Special filenames without extensions (like `Makefile` and `Dockerfile`) are handled
automatically.

### Safety & exclusions

This tool is intentionally conservative.

**Always-excluded file types** (never included, regardless of content):

```
hex, bin,
s19, s28, s37,
srec, mot,
xbin,
ihx, ihex
```

**Built-in excluded directories** (folder mode; skipped by name, independent of `.gitignore`):

```
.git, .hg, .svn, .idea, .vs,
__pycache__, .mypy_cache, .pytest_cache,
node_modules, dist, build, out, target,
bin, obj,
venv, .venv
```

> The built-in directory exclusions always apply, even with `.gitignore` honored — a
> folder in that list is skipped regardless of what your `.gitignore` says.

**Firmware content detection** — even with a text extension, a file is excluded if it
looks like firmware: Intel HEX records (`:10....`) or Motorola S-Record records
(`S19....`). Detection is by **content pattern**, not just extension.

**Binary detection** — files are excluded if they contain null bytes, fail text
heuristics, or have too high a binary-character ratio. This keeps out compiled objects and
encoded blobs.

### Internal safety limits (main-file mode)

To prevent runaway traversal of pathological dependency graphs:

- Maximum referenced files: **2000**
- Maximum traversal depth: **10 levels**
- Wildcard expansion: limited and scoped
- Bare filename search: capped

---

## Troubleshooting

- **The window doesn't appear / looks like it's hanging.** It's centered and forced to the
  front on launch; if it ever opens off-screen behind other windows, alt-tab to it. On
  frozen `.exe` builds the background console is hidden on purpose.
- **A file I wanted got skipped.** Check, in order: is its extension in the always-excluded
  list? Is it inside a built-in excluded directory (e.g. `dist`, `build`, `node_modules`)?
  Is it matched by `.gitignore` (turn that checkbox off to test)? Does it look binary or
  like firmware? Any one of these will exclude it.
- **`.gitignore` isn't being respected.** Make sure you're in **folder mode** — the
  checkbox only applies there and is disabled in main-file mode.
- **The folder picker shows the wrong style on Windows.** Folder mode uses the classic
  tree picker via the OS; if that call ever fails it falls back to the standard dialog.
- **Build fails complaining about the Python version.** The `.exe` build requires Python
  **3.13.12** exactly; install that version and retry.

---

## Use cases

- Preparing code for AI analysis
- Creating a single-file project snapshot
- Reviewing automation logic
- Archiving scripts with dependencies intact
- Sharing reproducible context without binaries

---

## License

Use, modify, and distribute freely. No warranty is implied. This tool prioritizes safety
over completeness by design.