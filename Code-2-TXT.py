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

# Approx. number of visual lines (Notepad++ style, i.e. \n-delimited rows)
# per output part when splitting. A split is only ever made on a file
# boundary, so individual parts may run somewhat over this to avoid
# breaking a file in half.
DEFAULT_SPLIT_LINES = 5000


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


def build_file_block(
    rel,
    absolute: Path,
    size: int,
    encoding: str,
    text: str,
    seg_index: int = 1,
    seg_total: int = 1,
    seg_line_start: Optional[int] = None,
    seg_line_end: Optional[int] = None,
) -> str:
    """
    Build the structured text block for a single file (no I/O).

    When seg_total > 1 the file was too large to fit in one part and has been
    split across multiple parts ON LINE BOUNDARIES. Each segment carries
    explicit continuation banners so a reader never mistakes the pieces for
    separate files or for the file's true beginning/end.
    """
    if text and not text.endswith("\n"):
        text = text + "\n"

    is_segmented = seg_total > 1

    parts: List[str] = []
    if is_segmented:
        parts.append("===== FILE START (CONTINUED) =====\n")
    else:
        parts.append("===== FILE START =====\n")
    parts.append(f"Path: {rel}\n")
    parts.append(f"Absolute: {absolute}\n")
    parts.append(f"Size: {size} bytes\n")
    parts.append(f"Encoding: {encoding}\n")

    if is_segmented:
        parts.append(
            f"*** NOTE: This single file was too large for one part and was "
            f"split across {seg_total} segments on line boundaries. ***\n"
        )
        parts.append(f"*** This is SEGMENT {seg_index} of {seg_total} of this ONE file. ***\n")
        if seg_line_start is not None and seg_line_end is not None:
            parts.append(
                f"*** Original-file lines {seg_line_start}-{seg_line_end} "
                f"(of the file's own numbering). ***\n"
            )
        if seg_index > 1:
            parts.append("*** Content below CONTINUES from the previous segment. ***\n")
        if seg_index < seg_total:
            parts.append("*** Content is CONTINUED in the next segment. ***\n")
        if seg_index == 1:
            parts.append(f"----- BEGIN CONTENT (segment {seg_index}/{seg_total}) -----\n")
        else:
            parts.append(f"----- RESUME CONTENT (segment {seg_index}/{seg_total}) -----\n")
    else:
        parts.append("----- BEGIN CONTENT -----\n")

    parts.append(text)

    if is_segmented:
        if seg_index < seg_total:
            parts.append(f"----- PAUSE CONTENT (segment {seg_index}/{seg_total}) -----\n")
            parts.append("===== FILE SEGMENT END (MORE IN NEXT PART) =====\n")
        else:
            parts.append(f"----- END CONTENT (segment {seg_index}/{seg_total}) -----\n")
            parts.append("===== FILE END (ALL SEGMENTS COMPLETE) =====\n")
    else:
        parts.append("----- END CONTENT -----\n")
        parts.append("===== FILE END =====\n")
    parts.append("\n")
    return "".join(parts)


def segment_oversized_block(
    label: str,
    rel,
    absolute: Path,
    size: int,
    encoding: str,
    text: str,
    body_budget: int,
) -> List[Tuple[str, str]]:
    """
    Split one file's content into multiple line-bounded segment blocks so each
    fits within `body_budget` editor lines of CONTENT. The split is always on a
    newline boundary (never mid-line). Returns a list of (label, block_text).

    body_budget is how many content lines may go in each segment; it should be
    the per-part line target minus the fixed overhead a block's header/footer
    adds, so a segment block stays near the requested part size.
    """
    if text and not text.endswith("\n"):
        text = text + "\n"
    lines = text.splitlines(keepends=True)
    total_lines = len(lines)

    # Guard: never allow a zero/negative budget; keep at least some content.
    per = max(50, body_budget)

    # How many segments will we need?
    seg_total = max(1, (total_lines + per - 1) // per)
    if seg_total == 1:
        # Fits after all; emit a normal single block.
        return [(label, build_file_block(rel, absolute, size, encoding, text))]

    out: List[Tuple[str, str]] = []
    for i in range(seg_total):
        start = i * per
        end = min(total_lines, start + per)
        chunk = "".join(lines[start:end])
        seg_index = i + 1
        seg_label = f"{label} (segment {seg_index}/{seg_total})"
        block = build_file_block(
            rel, absolute, size, encoding, chunk,
            seg_index=seg_index,
            seg_total=seg_total,
            seg_line_start=start + 1,
            seg_line_end=end,
        )
        out.append((seg_label, block))
    return out


def count_lines(s: str) -> int:
    """
    Count visual lines the way an editor (e.g. Notepad++) numbers them:
    one row per newline, plus one more if there is trailing content
    after the last newline.
    """
    if not s:
        return 0
    n = s.count("\n")
    if not s.endswith("\n"):
        n += 1
    return n


def write_output_in_parts(
    output_file: Path,
    header: str,
    items: List[Tuple[str, object, Path, int, str, str]],
    manifest_lines: List[str],
    split_lines: Optional[int] = DEFAULT_SPLIT_LINES,
) -> List[Path]:
    """
    Write the combined output, splitting into multiple part files when the
    total visual line count exceeds `split_lines`.

    Splits normally happen only between one file's end marker and the next
    file's start marker. If a SINGLE file is itself larger than the threshold,
    that file is split across parts on line boundaries, and every piece is
    clearly banner-marked as a continuation segment so a reader cannot mistake
    the pieces for separate files.

    items: list of (label, rel, absolute, size, encoding, text) in output order.
    manifest_lines: relative paths (or labels) for the overall manifest.

    Returns the list of files actually written.
    """
    output_file = output_file.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    header_lines = count_lines(header)

    # Build the un-split blocks first (one per file).
    whole_blocks: List[Tuple[str, str]] = []
    for label, rel, absolute, size, encoding, text in items:
        whole_blocks.append(
            (label, build_file_block(rel, absolute, size, encoding, text))
        )

    total_lines = header_lines + sum(count_lines(b) for _, b in whole_blocks)

    # No split requested, or it all fits: single file, original behavior + manifest.
    if not split_lines or split_lines <= 0 or total_lines <= split_lines:
        with output_file.open("w", encoding="utf-8", newline="\n") as out:
            out.write(header)
            for _, b in whole_blocks:
                out.write(b)
            out.write("=== MANIFEST (in order) ===\n")
            for m in manifest_lines:
                out.write(m + "\n")
        return [output_file]

    # Fixed overhead (header + segment banners) a block carries beyond its
    # content lines. Used to size content segments for oversized files.
    # A segmented block's non-content lines number roughly a dozen; budget
    # content generously below the per-part target so a segment stays in range.
    overhead = 14
    body_budget = max(50, split_lines - header_lines - overhead)

    # Expand items into final blocks, segmenting any single file whose block
    # alone exceeds the per-part line budget.
    blocks: List[Tuple[str, str]] = []
    any_segmented = False
    for (label, rel, absolute, size, encoding, text), (lbl, whole) in zip(items, whole_blocks):
        if count_lines(whole) + header_lines > split_lines:
            segs = segment_oversized_block(
                label, rel, absolute, size, encoding, text, body_budget
            )
            if len(segs) > 1:
                any_segmented = True
            blocks.extend(segs)
        else:
            blocks.append((label, whole))

    # --- Group blocks into parts. ---
    # An oversized file's segments are each their own unit here, so each can
    # occupy (most of) a part. Other files still split only on boundaries.
    parts: List[List[Tuple[str, str]]] = []
    current: List[Tuple[str, str]] = []
    current_lines = header_lines  # every part repeats the header

    for label, block in blocks:
        b_lines = count_lines(block)
        if current and (current_lines + b_lines) > split_lines:
            parts.append(current)
            current = []
            current_lines = header_lines
        current.append((label, block))
        current_lines += b_lines

    if current:
        parts.append(current)

    total_parts = len(parts)
    stem = output_file.stem
    suffix = output_file.suffix or ".txt"
    parent = output_file.parent

    written: List[Path] = []
    running_no = 0

    for idx, part in enumerate(parts, start=1):
        part_path = parent / f"{stem}.part{idx:02d}of{total_parts:02d}{suffix}"
        first_no = running_no + 1
        labels_in_part = [label for label, _ in part]
        last_no = running_no + len(part)

        with part_path.open("w", encoding="utf-8", newline="\n") as out:
            out.write(header)
            # Mark which part this is, right under the header.
            out.write(f"=== PART {idx} OF {total_parts} ===\n")
            out.write(
                f"This part contains entries {first_no}-{last_no} of the full "
                f"set (an 'entry' is a whole file, or one segment of a file "
                f"that was too large to fit in a single part).\n\n"
            )
            for label, block in part:
                out.write(block)

            # Per-part summary footer so an AI reading any single part can
            # understand the chunking and how the whole set is laid out.
            out.write("===== PART SUMMARY =====\n")
            out.write(
                "This text file is one part of a multi-part code dump that was "
                "split because it exceeded the line threshold.\n"
            )
            out.write(
                f"Split target: ~{split_lines} editor lines per part. Splits "
                "normally occur only between a file's '===== FILE END =====' "
                "and the next file's '===== FILE START ====='.\n"
            )
            if any_segmented:
                out.write(
                    "NOTE: One or more single files were larger than the "
                    "threshold and were split across parts ON LINE BOUNDARIES. "
                    "Those pieces are marked '===== FILE START (CONTINUED) =====' "
                    "and '===== FILE SEGMENT END (MORE IN NEXT PART) =====', with "
                    "a 'SEGMENT n of m' banner. Reassemble them in order to get "
                    "the original file; a label like 'foo.py (segment 2/3)' means "
                    "the same single file continued.\n"
                )
            out.write(f"Part {idx} of {total_parts}.\n")
            if idx > 1:
                out.write(
                    f"Previous part: {stem}.part{idx-1:02d}of{total_parts:02d}{suffix}\n"
                )
            if idx < total_parts:
                out.write(
                    f"Next part: {stem}.part{idx+1:02d}of{total_parts:02d}{suffix}\n"
                )
            out.write(f"\nEntries in THIS part ({first_no}-{last_no}), in order:\n")
            n = first_no
            for label in labels_in_part:
                out.write(f"  {n}. {label}\n")
                n += 1
            out.write("\nFull layout across ALL parts, in order:\n")
            alln = 0
            for pidx, p in enumerate(parts, start=1):
                for label, _ in p:
                    alln += 1
                    marker = "  <-- in this part" if pidx == idx else ""
                    out.write(f"  [part {pidx:02d}] {alln}. {label}{marker}\n")
            out.write("===== END PART SUMMARY =====\n")

        running_no = last_no
        written.append(part_path)

    return written


def combine_folder_mode(
    root_dir: Path,
    output_file: Path,
    exclude_dirs: Optional[Set[str]] = None,
    max_bytes: Optional[int] = None,
    split_lines: Optional[int] = DEFAULT_SPLIT_LINES,
) -> Tuple[int, List[Path]]:
    allow_exts = set(DEFAULT_TEXT_EXTS)
    ex_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        ex_dirs |= set(exclude_dirs)
    deny_exts = {e.lower() for e in ALWAYS_EXCLUDE_EXTS}

    output_file = output_file.resolve()
    root_dir = root_dir.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    included_files: List[str] = []
    items: List[Tuple[str, object, Path, int, str, str]] = []

    ts = datetime.now().isoformat(timespec="seconds")
    header = (
        "=== COMBINED TEXT DUMP (Folder Mode) ===\n"
        f"Root: {root_dir}\n"
        f"Generated: {ts}\n"
        f"Excluded dirs: {', '.join(sorted(ex_dirs)) if ex_dirs else 'None'}\n"
        f"Always-excluded extensions: {', '.join(sorted(deny_exts))}\n"
        f"Max bytes per file: {max_bytes if max_bytes is not None else 'None'}\n"
        "\n"
    )

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
                text, encoding = detect_and_decode(data)
            except Exception:
                continue

            try:
                rel = fpath.relative_to(root_dir)
            except ValueError:
                rel = fpath

            block_rel = str(rel)
            items.append((block_rel, rel, fpath.resolve(), len(data), encoding, text))
            included_files.append(str(rel))

    written = write_output_in_parts(
        output_file=output_file,
        header=header,
        items=items,
        manifest_lines=included_files,
        split_lines=split_lines,
    )

    return len(included_files), written


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
    split_lines: Optional[int] = DEFAULT_SPLIT_LINES,
) -> Tuple[int, List[Path]]:
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
        return 0, [output_file]

    # Compute a common project root for nice relative paths
    try:
        common = os.path.commonpath([str(p.parent) for p in order])
        project_root = Path(common).resolve()
    except Exception:
        project_root = start_dir

    ts = datetime.now().isoformat(timespec="seconds")
    header = (
        "=== COMBINED TEXT DUMP (Main-File Mode) ===\n"
        f"Root: {project_root}\n"
        f"Main file: {main_file}\n"
        f"Generated: {ts}\n"
        f"Always-excluded extensions: {', '.join(sorted(deny_exts))}\n"
        f"Max bytes per file: {max_bytes if max_bytes is not None else 'None'}\n"
        "\n"
    )

    # Second pass: build item tuples in the collected order
    items: List[Tuple[str, object, Path, int, str, str]] = []
    manifest_lines: List[str] = []
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
        items.append((str(rel), rel, real, len(data), encoding, text))
        manifest_lines.append(str(rel))

    written = write_output_in_parts(
        output_file=output_file,
        header=header,
        items=items,
        manifest_lines=manifest_lines,
        split_lines=split_lines,
    )

    return len(order), written
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
    from tkinter import simpledialog as sd
    resp = mb.askyesno(
        "Combine Mode",
        "Yes: Pick a single MAIN script file (append its referenced files).\n"
        "No:  Pick a FOLDER (combine all text-like files under it)."
    )

    def ask_split_lines() -> Optional[int]:
        """Prompt for split size. Returns lines-per-part, or None for no split."""
        want_split = mb.askyesno(
            "Split output?",
            "Split the output into multiple parts for easier chat-bot ingestion?\n\n"
            "Yes: split at about a set number of editor lines (file boundaries kept whole).\n"
            "No:  write a single combined file."
        )
        if not want_split:
            return None
        val = sd.askinteger(
            "Lines per part",
            "Approx. editor lines per part\n"
            "(splits only between files, so parts may run slightly over):",
            initialvalue=DEFAULT_SPLIT_LINES,
            minvalue=100,
        )
        # Cancel -> fall back to the default rather than no-split.
        return val if val else DEFAULT_SPLIT_LINES

    def report(out_paths: List[Path], count: int, what: str) -> None:
        if len(out_paths) == 1:
            where = str(out_paths[0])
        else:
            where = (
                f"{len(out_paths)} parts:\n  "
                + "\n  ".join(p.name for p in out_paths)
                + f"\n\nin: {out_paths[0].parent}"
            )
        mb.showinfo(
            "Done",
            f"Wrote {count} files ({what}) to:\n{where}\n\n"
            f"Excluded by extension: {', '.join(sorted(ALWAYS_EXCLUDE_EXTS))}\n"
            f"Also skipped Intel HEX / Motorola S-Record content."
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

        split_lines = ask_split_lines()

        try:
            count, written = combine_from_main_file_mode(
                main_file=Path(main_file),
                output_file=Path(out_file),
                max_bytes=None,
                split_lines=split_lines,
            )
            report(written, count, "main + referenced")
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

        split_lines = ask_split_lines()

        try:
            count, written = combine_folder_mode(
                root_dir=Path(root_dir),
                output_file=Path(out_file),
                exclude_dirs=None,
                max_bytes=None,
                split_lines=split_lines,
            )
            report(written, count, "folder mode")
        except Exception as e:
            mb.showerror("Error", f"Failed: {e}")
            sys.exit(1)


if __name__ == "__main__":

    main()