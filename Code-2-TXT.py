#!/usr/bin/env python3
# Code-2-TXT.py
# GUI-only, single-file tool.
# Modes:
# - Folder mode: combine all text-like files under a chosen folder (with exclusions).
# - Main-file mode: pick a main script (e.g., .atsb, .py, .ps1, .vb, etc.); it extracts
#   referenced files from within the same root directory and appends them (main first).
#
# Firmware/binary formats are excluded by extension and by content pattern.
# This avoids .hex/.bin/.s19/.mot/.xbin/etc. and Intel HEX / Motorola S-Record content.

import os
import sys
import re
from pathlib import Path
from datetime import datetime
from typing import Set, List, Tuple, Optional, Iterable, Deque
from collections import deque

# Always exclude these extensions (case-insensitive)
ALWAYS_EXCLUDE_EXTS: Set[str] = {
    "hex", "bin",          # generic binaries / Intel HEX common
    "s19", "s28", "s37",   # Motorola S-Record variants
    "srec", "mot",         # more S-Record extensions
    "xbin",                # various binary formats use this
    "ihx", "ihex",         # Intel HEX variants
}

# Common text/script/config extensions to consider by default
DEFAULT_TEXT_EXTS: Set[str] = {
    # Scripts
    "py", "pyw", "ps1", "psm1", "psd1", "bat", "cmd", "sh", "zsh", "fish",
    "vb", "vbs", "bas", "cls", "frm", "atsb",
    # Web / markup
    "html", "htm", "css", "scss", "sass", "less", "xml", "xsl", "svg",
    # Data / configs
    "json", "jsonc", "yaml", "yml", "toml", "ini", "cfg", "conf", "env", "properties",
    "csv", "tsv",
    # Code
    "js", "mjs", "cjs", "ts", "tsx", "jsx", "java", "kt", "kts",
    "c", "h", "cpp", "hpp", "cc", "hh", "cs", "go", "rs", "swift", "php", "r", "m", "mm",
    "sql",
    # Docs
    "txt", "md", "rst", "adoc", "log",
    # Build/other
    "gradle", "groovy", "cmake", "make", "mak", "dockerfile", "tex",
}

# Special filenames considered text even without extension (case-insensitive)
SPECIAL_TEXT_FILENAMES: Set[str] = {
    "makefile", "dockerfile", "license", "license.txt", "readme", "readme.md",
    "requirements", "pipfile", "pipfile.lock", "package.json", "package-lock.json",
    ".env", ".gitignore", ".gitattributes", ".editorconfig", ".prettierrc",
    ".eslintrc", ".pylintrc", ".flake8", "pyproject.toml",
}

# Common directories to skip in folder mode
DEFAULT_EXCLUDE_DIRS: Set[str] = {
    ".git", ".hg", ".svn", ".idea", ".vs",
    "__pycache__", ".mypy_cache", ".pytest_cache",
    "node_modules", "dist", "build", "out", "target",
    "bin", "obj",
    "venv", ".venv",
}

SREC_RE = re.compile(r"^\s*S[0-9A-Fa-f][0-9A-Fa-f]+\s*$")
IHEX_RE = re.compile(r"^\s*:[0-9A-Fa-f]+\s*$")

# For extracting candidate paths from scripts
QUOTED_STRING_RE = re.compile(r"""(['"])(.{1,260}?)\1""")
# include/import/source-like patterns capturing the next token or quoted path
INCLUDE_LIKE_RES = [
    re.compile(r"""(?i)\b(?:#include|include|uses|use|require|require_once|source|loadfile|load|dofile|execfile|Import-Module)\s*(?:\(|\s)\s*(['"]?)([^'"()\[\]\s]+)\1"""),
    # PowerShell dot-sourcing: . .\script.ps1 or . "path"
    re.compile(r"""(?m)^\s*\.\s+(['"]?)([^'"\s]+)\1"""),
    # shell 'source path'
    re.compile(r"""(?i)\bsource\s+(['"]?)([^'"\s]+)\1"""),
]

# Safety limits for main-file reference traversal
MAX_REFERENCED_FILES = 2000
MAX_TRAVERSAL_DEPTH = 10


def sniff_is_text(sample: bytes) -> bool:
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass
    printable = set(range(32, 127)) | {9, 10, 13}
    nontext = sum(1 for b in sample if b not in printable)
    ratio = nontext / max(1, len(sample))
    return ratio < 0.30


def looks_like_firmware_ascii(sample: bytes) -> bool:
    """
    Detect common ASCII firmware formats to exclude:
    - Motorola S-Record (lines like 'S19....')
    - Intel HEX (lines like ':10....')
    """
    if not sample:
        return False
    txt = sample.decode("ascii", errors="ignore")
    lines = [ln for ln in txt.splitlines() if ln.strip()]
    if not lines:
        return False
    lines = lines[:200]
    srec = sum(1 for ln in lines if SREC_RE.match(ln))
    ihex = sum(1 for ln in lines if IHEX_RE.match(ln))
    total = len(lines)
    if total >= 5 and (srec >= 0.6 * total or ihex >= 0.6 * total):
        return True
    return False


def detect_and_decode(data: bytes) -> Tuple[str, str]:
    if data.startswith(b"\xef\xbb\xbf"):
        text = data.decode("utf-8-sig")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-8-sig"
    if data.startswith(b"\xff\xfe\x00\x00"):
        text = data.decode("utf-32-le")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-32-le"
    if data.startswith(b"\x00\x00\xfe\xff"):
        text = data.decode("utf-32-be")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-32-be"
    if data.startswith(b"\xff\xfe"):
        text = data.decode("utf-16-le")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-16-le"
    if data.startswith(b"\xfe\xff"):
        text = data.decode("utf-16-be")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-16-be"
    try:
        text = data.decode("utf-8")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "utf-8"
    except UnicodeDecodeError:
        pass
    try:
        text = data.decode("cp1252")
        return text.replace("\r\n", "\n").replace("\r", "\n"), "cp1252"
    except UnicodeDecodeError:
        pass
    text = data.decode("latin-1", errors="strict")
    return text.replace("\r\n", "\n").replace("\r", "\n"), "latin-1"


def should_consider_text_file(path: Path, allow_exts: Set[str]) -> bool:
    name_lower = path.name.lower()
    if name_lower in SPECIAL_TEXT_FILENAMES:
        return True
    for special in ("dockerfile", "makefile", "license", "readme"):
        if name_lower.startswith(special + "."):
            return True
    ext = path.suffix.lower().lstrip(".")
    if not ext:
        return False
    return ext in allow_exts


def write_file_block(out, fpath: Path, root_dir: Path, data: bytes) -> None:
    size = len(data)
    text, encoding = detect_and_decode(data)
    try:
        rel = fpath.relative_to(root_dir)
    except ValueError:
        rel = fpath
    out.write("===== FILE START =====\n")
    out.write(f"Path: {rel}\n")
    out.write(f"Absolute: {fpath.resolve()}\n")
    out.write(f"Size: {size} bytes\n")
    out.write(f"Encoding: {encoding}\n")
    out.write("----- BEGIN CONTENT -----\n")
    if text and not text.endswith("\n"):
        text = text + "\n"
    out.write(text)
    out.write("----- END CONTENT -----\n")
    out.write("===== FILE END =====\n")
    out.write("\n")


def combine_folder_mode(
    root_dir: Path,
    output_file: Path,
    exclude_dirs: Optional[Set[str]] = None,
    max_bytes: Optional[int] = None,
) -> int:
    allow_exts = set(DEFAULT_TEXT_EXTS)
    ex_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        ex_dirs |= set(exclude_dirs)
    deny_exts = {e.lower() for e in ALWAYS_EXCLUDE_EXTS}

    output_file = output_file.resolve()
    root_dir = root_dir.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    included_files: List[str] = []

    with output_file.open("w", encoding="utf-8", newline="\n") as out:
        ts = datetime.now().isoformat(timespec="seconds")
        out.write("=== COMBINED TEXT DUMP (Folder Mode) ===\n")
        out.write(f"Root: {root_dir}\n")
        out.write(f"Generated: {ts}\n")
        out.write(f"Excluded dirs: {', '.join(sorted(ex_dirs)) if ex_dirs else 'None'}\n")
        out.write(f"Always-excluded extensions: {', '.join(sorted(deny_exts))}\n")
        out.write(f"Max bytes per file: {max_bytes if max_bytes is not None else 'None'}\n")
        out.write("\n")

        for current_root, dirs, files in os.walk(root_dir, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if d not in ex_dirs]

            for fname in files:
                fpath = Path(current_root) / fname
                try:
                    if fpath.resolve() == output_file:
                        continue
                except Exception:
                    pass

                ext = fpath.suffix.lower().lstrip(".")
                if ext in deny_exts:
                    continue

                try:
                    size = fpath.stat().st_size
                except OSError:
                    continue
                if max_bytes is not None and size > max_bytes:
                    continue

                candidate = should_consider_text_file(fpath, allow_exts=allow_exts)

                try:
                    with fpath.open("rb") as fb:
                        sample = fb.read(8192)
                except OSError:
                    continue

                if looks_like_firmware_ascii(sample):
                    continue

                if not candidate and not sniff_is_text(sample):
                    continue

                try:
                    if size <= len(sample):
                        data = sample
                    else:
                        with fpath.open("rb") as fb:
                            data = fb.read()
                except OSError:
                    continue

                if looks_like_firmware_ascii(data[:8192]) or not sniff_is_text(data[:8192]):
                    continue

                try:
                    # decoding happens in write_file_block
                    pass
                except Exception:
                    continue

                write_file_block(out, fpath, root_dir, data)
                try:
                    rel = fpath.relative_to(root_dir)
                except ValueError:
                    rel = fpath
                included_files.append(str(rel))

        out.write("=== MANIFEST (in order) ===\n")
        for p in included_files:
            out.write(p + "\n")

    return len(included_files)


def has_allowed_ext(path_str: str, allow_exts: Set[str], deny_exts: Set[str]) -> bool:
    # catch names like "Dockerfile", "Makefile" (no dot)
    name = Path(path_str).name
    lower = name.lower()
    if lower in SPECIAL_TEXT_FILENAMES:
        return True
    ext = Path(path_str).suffix.lower().lstrip(".")
    if not ext:
        return False
    if ext in deny_exts:
        return False
    return ext in allow_exts


def extract_candidate_paths(text: str, allow_exts: Set[str], deny_exts: Set[str]) -> Set[str]:
    """
    Heuristically extract file path strings from script text.
    We look for:
      - Quoted strings
      - include/import/source-like statements with a following token or quoted path
    Only keep candidates whose extension is allowed (and not denied).
    """
    found: Set[str] = set()

    # Quoted strings
    for m in QUOTED_STRING_RE.finditer(text):
        s = m.group(2).strip()
        if has_allowed_ext(s, allow_exts, deny_exts):
            found.add(s)

    # include-like tokens
    for rx in INCLUDE_LIKE_RES:
        for m in rx.finditer(text):
            s = m.group(2).strip()
            if has_allowed_ext(s, allow_exts, deny_exts):
                found.add(s)

    return found


def resolve_candidates(
    candidates: Iterable[str],
    root_dir: Path,
) -> List[Path]:
    """
    Resolve candidate path strings against root_dir.
    - Expands env vars and ~
    - Accepts absolute paths only if they lie within root_dir
    - Supports simple wildcards (*, ?) relative to root_dir
    - Normalizes separators
    """
    resolved: List[Path] = []
    for s in candidates:
        if not s:
            continue
        # Expand env/user
        s2 = os.path.expandvars(os.path.expanduser(s))
        # Normalize slashes
        s2 = s2.replace("\\", os.sep).replace("/", os.sep)

        p = Path(s2)
        # If it's absolute, keep only if within root_dir
        try:
            if p.is_absolute():
                try:
                    rp = p.resolve()
                except Exception:
                    continue
                try:
                    rp.relative_to(root_dir)
                    # inside root
                    if rp.exists():
                        resolved.append(rp)
                except ValueError:
                    # outside root_dir; skip
                    continue
            else:
                # Relative or with wildcards
                # Handle globs
                if any(ch in s2 for ch in "*?"):
                    for match in (root_dir / s2).parent.glob(Path(s2).name):
                        try:
                            rp = match.resolve()
                        except Exception:
                            continue
                        try:
                            rp.relative_to(root_dir)
                        except ValueError:
                            continue
                        if rp.exists():
                            resolved.append(rp)
                else:
                    rp = (root_dir / s2).resolve()
                    try:
                        rp.relative_to(root_dir)
                    except ValueError:
                        continue
                    if rp.exists():
                        resolved.append(rp)
        except Exception:
            continue
    # Deduplicate while preserving order
    seen = set()
    out: List[Path] = []
    for p in resolved:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def combine_from_main_file_mode(
    main_file: Path,
    output_file: Path,
    max_bytes: Optional[int] = None,
) -> int:
    """
    Start from main_file (included first), parse it to find referenced files,
    resolve them (even if they live outside the main file's folder), and append.
    After collecting, compute a common project root for nice relative paths.
    """
    allow_exts = set(DEFAULT_TEXT_EXTS)
    deny_exts = {e.lower() for e in ALWAYS_EXCLUDE_EXTS}

    main_file = main_file.resolve()
    start_dir = main_file.parent.resolve()
    output_file = output_file.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    visited: Set[Path] = set()
    order: List[Path] = []

    def file_ok_to_include(p: Path, sample: bytes) -> bool:
        if p.suffix.lower().lstrip(".") in deny_exts:
            return False
        if looks_like_firmware_ascii(sample):
            return False
        if not sniff_is_text(sample):
            return False
        return True

    def resolve_one(ref: str, current_dir: Path) -> List[Path]:
        """
        Resolve a single reference string relative to the file that mentioned it.
        - Expands env and ~
        - If absolute, include if it exists.
        - If relative, resolve against current_dir.
        - If bare filename not found directly, search recursively under start_dir.
        """
        out: List[Path] = []
        if not ref:
            return out
        s2 = os.path.expandvars(os.path.expanduser(ref))
        s2 = s2.replace("\\", os.sep).replace("/", os.sep)
        p = Path(s2)
        try:
            if p.is_absolute():
                rp = p.resolve()
                if rp.exists():
                    out.append(rp)
            else:
                # try direct relative
                rp = (current_dir / p).resolve()
                if rp.exists():
                    out.append(rp)
                else:
                    # bare name search under the start_dir (one safety cap)
                    if p.parent == Path("."):
                        count = 0
                        for match in start_dir.rglob(p.name):
                            try:
                                rpm = match.resolve()
                            except Exception:
                                continue
                            if rpm.exists():
                                out.append(rpm)
                                count += 1
                                if count >= 100:
                                    break
        except Exception:
            pass
        # dedupe per call
        dedup = []
        seen = set()
        for q in out:
            if q not in seen:
                seen.add(q)
                dedup.append(q)
        return dedup

    # First pass: collect all files in BFS order (don’t write yet)
    queue: Deque[Tuple[Path, int]] = deque()
    queue.append((main_file, 0))

    contents: dict[Path, bytes] = {}

    while queue and len(order) < MAX_REFERENCED_FILES:
        fpath, depth = queue.popleft()
        try:
            real = fpath.resolve()
        except Exception:
            continue
        if real in visited:
            continue

        # Read data
        try:
            size = real.stat().st_size
            if max_bytes is not None and size > max_bytes:
                visited.add(real)
                continue
            with real.open("rb") as fb:
                data = fb.read()
        except OSError:
            visited.add(real)
            continue

        if not file_ok_to_include(real, data[:8192]):
            visited.add(real)
            continue

        # Keep
        contents[real] = data
        order.append(real)
        visited.add(real)

        # Traverse further if depth allows
        if depth >= MAX_TRAVERSAL_DEPTH:
            continue

        # Extract references and resolve them relative to this file’s folder
        try:
            text, _enc = detect_and_decode(data)
        except Exception:
            continue

        cands = extract_candidate_paths(text, allow_exts=allow_exts, deny_exts=deny_exts)
        resolved: List[Path] = []
        for s in cands:
            resolved.extend(resolve_one(s, current_dir=real.parent))

        for rp in resolved:
            if rp not in visited:
                queue.append((rp, depth + 1))
                if len(order) + len(queue) >= MAX_REFERENCED_FILES:
                    break

    if not order:
        # Nothing collected; write a minimal file
        with output_file.open("w", encoding="utf-8", newline="\n") as out:
            out.write("=== COMBINED TEXT DUMP (Main-File Mode) ===\n")
            out.write(f"Root: {start_dir}\n")
            out.write(f"Main file: {main_file}\n")
            out.write("No files included.\n")
        return 0

    # Compute a common project root for nice relative paths
    try:
        common = os.path.commonpath([str(p.parent) for p in order])
        project_root = Path(common).resolve()
    except Exception:
        project_root = start_dir

    # Second pass: write out in the collected order
    with output_file.open("w", encoding="utf-8", newline="\n") as out:
        ts = datetime.now().isoformat(timespec="seconds")
        out.write("=== COMBINED TEXT DUMP (Main-File Mode) ===\n")
        out.write(f"Root: {project_root}\n")
        out.write(f"Main file: {main_file}\n")
        out.write(f"Generated: {ts}\n")
        out.write(f"Always-excluded extensions: {', '.join(sorted(deny_exts))}\n")
        out.write(f"Max bytes per file: {max_bytes if max_bytes is not None else 'None'}\n")
        out.write("\n")

        for real in order:
            data = contents[real]
            try:
                rel = real.relative_to(project_root)
            except ValueError:
                rel = real
            try:
                text, encoding = detect_and_decode(data)
            except Exception:
                continue

            out.write("===== FILE START =====\n")
            out.write(f"Path: {rel}\n")
            out.write(f"Absolute: {real}\n")
            out.write(f"Size: {len(data)} bytes\n")
            out.write(f"Encoding: {encoding}\n")
            out.write("----- BEGIN CONTENT -----\n")
            if text and not text.endswith("\n"):
                text += "\n"
            out.write(text)
            out.write("----- END CONTENT -----\n")
            out.write("===== FILE END =====\n")
            out.write("\n")

        out.write("=== MANIFEST (in order) ===\n")
        for real in order:
            try:
                rel = real.relative_to(project_root)
            except ValueError:
                rel = real
            out.write(str(rel) + "\n")

    return len(order)
def main():
    # Pure GUI to avoid CLI path issues
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox
    except Exception:
        print("tkinter GUI not available. Please install/enable it for your Python.", file=sys.stderr)
        sys.exit(2)

    root = tk.Tk()
    root.withdraw()

    # Ask user which mode
    from tkinter import messagebox as mb
    resp = mb.askyesno(
        "Combine Mode",
        "Yes: Pick a single MAIN script file (append its referenced files).\n"
        "No:  Pick a FOLDER (combine all text-like files under it)."
    )

    if resp:
        # Main-file mode
        filetypes = [
            ("Script files", "*.atsb *.py *.ps1 *.vb *.vbs *.bas *.cls *.frm *.cmd *.bat *.sh *.psm1 *.psd1"),
            ("All files", "*.*"),
        ]
        main_file = filedialog.askopenfilename(
            title="Select main script file",
            filetypes=filetypes
        )
        if not main_file:
            sys.exit(0)

        out_file = filedialog.asksaveasfilename(
            title="Save combined file as",
            defaultextension=".txt",
            initialfile=Path(main_file).with_suffix(".txt").name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not out_file:
            sys.exit(0)

        try:
            count = combine_from_main_file_mode(
                main_file=Path(main_file),
                output_file=Path(out_file),
                max_bytes=None,
            )
            mb.showinfo(
                "Done",
                f"Wrote {count} files (main + referenced) to:\n{out_file}\n\n"
                f"Excluded by extension: {', '.join(sorted(ALWAYS_EXCLUDE_EXTS))}\n"
                f"Also skipped Intel HEX / Motorola S-Record content."
            )
        except Exception as e:
            mb.showerror("Error", f"Failed: {e}")
            sys.exit(1)

    else:
        # Folder mode
        root_dir = filedialog.askdirectory(title="Select root folder to scan")
        if not root_dir:
            sys.exit(0)
        out_file = filedialog.asksaveasfilename(
            title="Save combined file as",
            defaultextension=".txt",
            initialfile="combined.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not out_file:
            sys.exit(0)

        try:
            count = combine_folder_mode(
                root_dir=Path(root_dir),
                output_file=Path(out_file),
                exclude_dirs=None,
                max_bytes=None,
            )
            mb.showinfo(
                "Done",
                f"Wrote {count} files to:\n{out_file}\n\n"
                f"Excluded by extension: {', '.join(sorted(ALWAYS_EXCLUDE_EXTS))}\n"
                f"Also skipped Intel HEX / Motorola S-Record content."
            )
        except Exception as e:
            mb.showerror("Error", f"Failed: {e}")
            sys.exit(1)


if __name__ == "__main__":

    main()
