# Combine Text GUI (Specialized)

A **single-file, GUI-only Python tool** that combines text and script files into one structured output file.

It is designed for **code review, auditing, archiving, AI ingestion, and documentation** while **safely excluding firmware and binary formats** (including Intel HEX and Motorola S-Record).

No command-line usage. No arguments. Just run it and use the dialogs.

---

## Options dialog

On launch, a single options window lets you choose everything at once and
press **OK**:

- **Mode** (pick one, each explained in the window):
  - *Main-file mode* — pick one main script; referenced files are appended.
  - *Folder mode* — pick a folder; all text-like files under it are combined.
- **Split output into multiple parts** (checkbox):
  - *Off* (default) — everything goes into one file (original behavior).
  - *On* — output is split near a chosen line count. Set **Lines per part**
    with the spinbox (default 5000, max 100000). Splits land on file
    boundaries; a file larger than the limit is split with clear
    continuation markers so the pieces aren't mistaken for separate files.

---

## Features

### Two Operating Modes

When launched, the tool asks which mode to use:

### 1. Main-File Mode (Dependency-Aware)

- Select a **single “main” script** (e.g. `.atsb`, `.py`, `.ps1`, `.vb`, `.bat`)
- The tool:
  - Includes the main file **first**
  - Scans its contents for referenced files (`include`, `source`, `Import-Module`, quoted paths, etc.)
  - Recursively resolves and appends those files
  - Uses **breadth-first traversal** with safety limits
- Produces a combined output with a clear file boundary format

Ideal for:
- Script bundles
- Automation frameworks
- Projects with scattered helper files
- Sending a self-contained context to an LLM

---

### 2. Folder Mode (Bulk Collection)

- Select a **root folder**
- Recursively combines **all text-like files** under it
- Automatically skips:
  - Build artifacts
  - VCS folders
  - Virtual environments
  - Node modules
- Each included file is written with metadata and clear separators

Ideal for:
- Codebase snapshots
- Configuration audits
- Documentation dumps
- Archival or review purposes

---

## Safety & Exclusions

This tool is intentionally conservative.

### Always-Excluded File Types

These extensions are **never included**, regardless of content:

```
hex, bin,
s19, s28, s37,
srec, mot,
xbin,
ihx, ihex
```

### Firmware Content Detection

Even if a file has a text extension, it will be excluded if it **looks like firmware**, including:

- Intel HEX records (`:10....`)
- Motorola S-Record records (`S19....`)

Detection is based on **content patterns**, not just extensions.

### Binary Detection

Files are excluded if:
- They contain null bytes
- They fail text heuristics
- The binary character ratio is too high

This prevents accidental inclusion of compiled objects or encoded blobs.

---

## Supported Text Types

### Scripts & Code

- Python, PowerShell, Batch, Shell
- VB / VBA
- C / C++ / C#
- Java, Go, Rust, Swift
- JavaScript / TypeScript
- SQL

### Config & Data

- JSON, YAML, TOML
- INI / CFG / CONF
- CSV / TSV
- `.env`

### Docs & Build Files

- `.txt`, `.md`, `.rst`, `.log`
- `Makefile`, `Dockerfile`
- `README`, `LICENSE`
- `pyproject.toml`, `package.json`

Special filenames without extensions are handled automatically.

---

## Output Format

Each file is wrapped in a structured block:

===== FILE START =====
Path: relative/path/to/file
Absolute: C:\full\path\to\file
Size: 1234 bytes
Encoding: utf-8
----- BEGIN CONTENT -----
(file contents)
----- END CONTENT -----
===== FILE END =====

yaml
Copy code

At the end of the output, a **manifest** lists all included files in order.

### Split output (when enabled)

When splitting is on and the content exceeds the line target, output is
written as numbered parts: `name.part01of03.txt`, `name.part02of03.txt`, etc.

- Parts split on file boundaries where possible.
- A single file larger than the threshold is split across parts on line
  boundaries. Its pieces use `===== FILE START (CONTINUED) =====`, a
  `SEGMENT n of m` banner, and `===== FILE SEGMENT END (MORE IN NEXT PART) =====`
  so they read as one continued file, not separate ones. Reassembling the
  segments in order reproduces the original file exactly.
- Each part ends with a summary footer listing the entries in that part and
  the full layout across all parts, so a tool reading any single part can
  understand the chunking.

---

## Building the .exe (Windows)

A `BUILD_EXE.bat` is included to produce a standalone `dist\Code-2-TXT.exe`.

Requirements:
- **Python 3.13.12 specifically.** The script checks the exact version and,
  if it's missing, prints the download link and stops.
- Build dependencies are pinned in `requirements.txt` (PyInstaller +
  hooks-contrib). The app itself has no runtime dependencies beyond the
  Python standard library.

Steps:
1. Install Python 3.13.12 (tick "Add python.exe to PATH" during install).
2. Double-click `BUILD_EXE.bat` (or run it from a terminal).
3. When it finishes, the executable is at `dist\Code-2-TXT.exe`.

The build reads the version from `version.txt` (a single line like `1.0.0`)
and embeds it as the Windows file version, visible under
**Properties > Details** on the built `.exe`. To change the version, edit
`version.txt` and rebuild.

---

## Usage

### Requirements

- Python **3.9+**
- `tkinter` available (default on most Python installations)

### Run

```bash
python combine_text_gui_specialized.py
The GUI will prompt you to select a mode and choose files or folders.

Internal Safety Limits
To prevent runaway traversal in Main-File Mode:

Maximum referenced files: 2000

Maximum traversal depth: 10 levels

Wildcard expansion: limited and scoped

Bare filename search: capped

These limits are intentional and protect against pathological dependency graphs.

Use Cases
Preparing code for AI analysis

Creating a single-file project snapshot

Reviewing automation logic

Archiving scripts with dependencies intact

Sharing reproducible context without binaries

License
Use, modify, and distribute freely.

No warranty is implied. This tool prioritizes safety over completeness by design.
