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

# ----------------------------------------------------------------------------
# .gitignore support (pure standard library; no external deps)
#
# Implements the parts of the gitignore spec that matter for excluding files
# from a code dump: per-line patterns, comments, blank lines, negation (!),
# directory-only patterns (trailing /), anchoring (leading /), the **
# wildcards, and single-level * / ? / [..] matching that does NOT cross "/".
# Patterns from nested .gitignore files apply relative to the directory that
# contains them, and later patterns override earlier ones (last match wins).
# ----------------------------------------------------------------------------


def _gitignore_translate(pattern: str) -> str:
    """
    Translate one gitignore glob pattern body (no leading '!', no trailing '/',
    anchoring already stripped by the caller) into a regular-expression string
    that matches a forward-slash-separated relative path.

    '*'  -> matches anything except '/'
    '?'  -> matches a single char except '/'
    '**' -> matches across '/' boundaries, per gitignore rules
    '[..]' character classes are passed through.
    """
    i = 0
    n = len(pattern)
    res: List[str] = []
    while i < n:
        c = pattern[i]
        if c == "*":
            # Look for a run of '*'
            if i + 1 < n and pattern[i + 1] == "*":
                # consume all consecutive '*'
                j = i
                while j < n and pattern[j] == "*":
                    j += 1
                before = pattern[i - 1] if i > 0 else ""
                after = pattern[j] if j < n else ""
                if (before in ("", "/")) and (after in ("", "/")):
                    # A path-spanning '**'
                    if after == "/":
                        # '**/' -> zero or more leading path segments
                        res.append("(?:.*/)?")
                        j += 1  # also consume the '/'
                    else:
                        res.append(".*")
                else:
                    # '**' not isolated -> treat as a single-segment '*'
                    res.append("[^/]*")
                i = j
                continue
            else:
                res.append("[^/]*")
                i += 1
                continue
        elif c == "?":
            res.append("[^/]")
            i += 1
        elif c == "[":
            # character class: copy until matching ']'
            j = i + 1
            if j < n and pattern[j] in ("!", "^"):
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                # no closing bracket: treat '[' literally
                res.append(re.escape("["))
                i += 1
            else:
                cls = pattern[i:j + 1]
                # gitignore uses '!' for negation inside classes like regex '^'
                if cls.startswith("[!"):
                    cls = "[^" + cls[2:]
                res.append(cls)
                i = j + 1
        else:
            res.append(re.escape(c))
            i += 1
    return "".join(res)


class _GitignoreRule:
    __slots__ = ("regex", "negation", "dir_only", "base")

    def __init__(self, regex: "re.Pattern", negation: bool, dir_only: bool, base: str):
        self.regex = regex
        self.negation = negation
        self.dir_only = dir_only
        self.base = base  # POSIX relative dir (from root) the rule is anchored under, "" for root


def _compile_gitignore_line(line: str, base: str) -> Optional[_GitignoreRule]:
    """
    Compile a single raw line from a .gitignore located at relative dir `base`
    (POSIX, '' for the scan root). Returns None for blanks/comments.
    """
    # Strip a trailing CR (Windows) and a single trailing newline already gone.
    raw = line.rstrip("\n").rstrip("\r")
    # Leading whitespace is significant only if escaped; gitignore trims
    # trailing spaces unless escaped with a backslash. Keep it simple/robust:
    if not raw.strip():
        return None
    if raw.lstrip().startswith("#"):
        return None

    s = raw
    negation = s.startswith("!")
    if negation:
        s = s[1:]
    # Unescape leading '\#' / '\!'
    if s.startswith("\\#") or s.startswith("\\!"):
        s = s[1:]

    # Trailing spaces are ignored unless escaped (we drop unescaped trailing ws)
    s = re.sub(r"(?<!\\)\s+$", "", s)

    dir_only = s.endswith("/")
    if dir_only:
        s = s[:-1]

    if not s:
        return None

    # A pattern containing a slash anywhere (other than a trailing one) is
    # anchored to the .gitignore's location. Otherwise it can match at any depth.
    anchored = "/" in s
    if s.startswith("/"):
        s = s[1:]
        anchored = True

    body = _gitignore_translate(s)

    if anchored:
        regex_str = r"^" + body + r"(?:/.*)?$"
    else:
        # match the pattern as a full path segment-run at any depth
        regex_str = r"(?:^|.*/)" + body + r"(?:/.*)?$"

    try:
        regex = re.compile(regex_str)
    except re.error:
        return None
    return _GitignoreRule(regex, negation, dir_only, base)


class GitignoreMatcher:
    """
    Collects gitignore rules discovered while walking a tree and answers
    'is this path ignored?' using last-match-wins semantics.

    All paths handed to this matcher must be POSIX-style relative paths from
    the scan root (e.g. 'src/foo.py', 'build').
    """

    def __init__(self) -> None:
        self.rules: List[_GitignoreRule] = []

    def add_file(self, gitignore_path: Path, base_rel: str) -> None:
        try:
            with gitignore_path.open("rb") as fb:
                data = fb.read()
        except OSError:
            return
        try:
            text = data.decode("utf-8-sig")
        except UnicodeDecodeError:
            try:
                text = data.decode("latin-1")
            except Exception:
                return
        for line in text.splitlines():
            rule = _compile_gitignore_line(line, base_rel)
            if rule is not None:
                self.rules.append(rule)

    def add_lines(self, lines: Iterable[str], base_rel: str = "") -> None:
        for line in lines:
            rule = _compile_gitignore_line(line, base_rel)
            if rule is not None:
                self.rules.append(rule)

    def is_ignored(self, rel_posix: str, is_dir: bool) -> bool:
        ignored = False
        for rule in self.rules:
            # Apply the rule only at/below its own base directory.
            if rule.base:
                prefix = rule.base + "/"
                if rel_posix == rule.base:
                    sub = ""
                elif rel_posix.startswith(prefix):
                    sub = rel_posix[len(prefix):]
                else:
                    continue
            else:
                sub = rel_posix
            if not sub:
                continue
            if rule.dir_only:
                # A trailing-slash pattern matches the directory itself AND
                # anything beneath it. For a non-directory we can only match it
                # by virtue of an ancestor directory matching, so test each
                # ancestor segment-run against the (directory) pattern.
                matched = False
                if is_dir and rule.regex.match(sub):
                    matched = True
                else:
                    parts = sub.split("/")
                    for k in range(1, len(parts)):
                        if rule.regex.match("/".join(parts[:k])):
                            matched = True
                            break
                if matched:
                    ignored = not rule.negation
                continue
            if rule.regex.match(sub):
                ignored = not rule.negation
        return ignored


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
    use_gitignore: bool = True,
) -> Tuple[int, List[Path]]:
    allow_exts = set(DEFAULT_TEXT_EXTS)
    ex_dirs = set(DEFAULT_EXCLUDE_DIRS)
    if exclude_dirs:
        ex_dirs |= set(exclude_dirs)
    deny_exts = {e.lower() for e in ALWAYS_EXCLUDE_EXTS}

    output_file = output_file.resolve()
    root_dir = root_dir.resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    # Build the .gitignore matcher. Git always ignores the .git directory and
    # honors a repo's .gitignore files; we additionally seed it with that so a
    # tree that has .git in ex_dirs still behaves the same with/without it.
    gi: Optional[GitignoreMatcher] = None
    gitignore_active = False
    if use_gitignore:
        gi = GitignoreMatcher()
        gi.add_lines([".git/"], base_rel="")

    def rel_posix(p: Path) -> str:
        try:
            r = p.resolve().relative_to(root_dir)
        except Exception:
            return ""
        s = r.as_posix()
        return "" if s == "." else s

    included_files: List[str] = []
    items: List[Tuple[str, object, Path, int, str, str]] = []

    ts = datetime.now().isoformat(timespec="seconds")
    header = (
        "=== COMBINED TEXT DUMP (Folder Mode) ===\n"
        f"Root: {root_dir}\n"
        f"Generated: {ts}\n"
        f"Excluded dirs: {', '.join(sorted(ex_dirs)) if ex_dirs else 'None'}\n"
        f"Always-excluded extensions: {', '.join(sorted(deny_exts))}\n"
        f"Honoring .gitignore: {'yes' if use_gitignore else 'no'}\n"
        f"Max bytes per file: {max_bytes if max_bytes is not None else 'None'}\n"
        "\n"
    )

    for current_root, dirs, files in os.walk(root_dir, topdown=True, followlinks=False):
        cur_path = Path(current_root)

        # Load any .gitignore in THIS directory before deciding what to prune,
        # so its rules apply to the current dir's children.
        if gi is not None:
            gif = cur_path / ".gitignore"
            if gif.is_file():
                base = rel_posix(cur_path)
                gi.add_file(gif, base)
                gitignore_active = True

        # Prune excluded dirs (by name) and gitignored dirs (by path).
        kept_dirs = []
        for d in dirs:
            if d in ex_dirs:
                continue
            if gi is not None:
                drel = rel_posix(cur_path / d)
                if drel and gi.is_ignored(drel, is_dir=True):
                    continue
            kept_dirs.append(d)
        dirs[:] = kept_dirs

        for fname in files:
            fpath = Path(current_root) / fname
            try:
                if fpath.resolve() == output_file:
                    continue
            except Exception:
                pass

            if gi is not None:
                frel = rel_posix(fpath)
                if frel and gi.is_ignored(frel, is_dir=False):
                    continue

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


def resource_path(name: str) -> str:
    """
    Locate a resource bundled with the app (e.g. icon.ico).

    When frozen by PyInstaller, bundled data is extracted to sys._MEIPASS.
    When running from source, it sits next to this script.
    """
    base = getattr(sys, "_MEIPASS", None)
    if not base:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, name)


def _hide_console_window_best_effort():
    """
    If this process has a console window (PyInstaller --console build),
    hide it when launching the GUI so no black window sits in the
    background or the taskbar. No-op on non-Windows, and only for frozen
    exe builds so it never hides the user's own terminal during dev.
    """
    if not sys.platform.startswith("win"):
        return
    if not getattr(sys, "frozen", False):
        return
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        user32 = ctypes.windll.user32
        hwnd = kernel32.GetConsoleWindow()
        if hwnd:
            SW_HIDE = 0  # fully hide (not just minimize) so it leaves no taskbar entry
            user32.ShowWindow(hwnd, SW_HIDE)
    except Exception:
        pass


def main():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    SPLIT_MIN = 100
    SPLIT_MAX = 100000

    _hide_console_window_best_effort()
    root = tk.Tk()
    root.title("Code-2-TXT")
    root.resizable(False, False)
    try:
        if sys.platform.startswith("win"):
            # default= applies the icon to the whole app instance (taskbar too),
            # overriding the inherited console/shim icon.
            root.iconbitmap(default=resource_path("icon.ico"))
    except Exception:
        pass

    mode = tk.StringVar(value="main")
    split_on = tk.BooleanVar(value=False)
    gitignore_on = tk.BooleanVar(value=True)
    split_val = tk.StringVar(value=str(DEFAULT_SPLIT_LINES))
    # Holds the user's confirmed choice; stays None if they close/cancel.
    choice = {"ok": False}

    pad_x = 14

    tk.Label(root, text="What do you want to do?",
             font=("Segoe UI", 11, "bold")).grid(
        row=0, column=0, sticky="w", padx=pad_x, pady=(12, 4))

    tk.Radiobutton(root, text="Main-file mode  (pick one script; its references are appended)",
                   variable=mode, value="main", command=lambda: sync()).grid(
        row=1, column=0, sticky="w", padx=pad_x)
    tk.Radiobutton(root, text="Folder mode  (pick a folder; all text files under it are combined)",
                   variable=mode, value="folder", command=lambda: sync()).grid(
        row=2, column=0, sticky="w", padx=pad_x)

    ttk.Separator(root, orient="horizontal").grid(
        row=3, column=0, sticky="ew", padx=pad_x, pady=10)

    spin_holder = tk.Frame(root)

    def sync():
        state = "normal" if split_on.get() else "disabled"
        spin.config(state=state)
        spin_lbl.config(state=state)
        gi_state = "normal" if mode.get() == "folder" else "disabled"
        gi_check.config(state=gi_state)
        gi_note.config(state=gi_state)

    tk.Checkbutton(root, text="Split output into multiple parts",
                   variable=split_on, command=sync,
                   font=("Segoe UI", 10, "bold")).grid(
        row=4, column=0, sticky="w", padx=pad_x)
    tk.Label(root,
             text=("Off = one big file (original behavior).\n"
                   "On = split near the line count below; big files are split\n"
                   "with clear continuation markers."),
             fg="#555555", justify="left").grid(
        row=5, column=0, sticky="w", padx=pad_x + 22, pady=(2, 4))

    spin_holder.grid(row=6, column=0, sticky="w", padx=pad_x + 22, pady=(0, 4))
    spin_lbl = tk.Label(spin_holder, text="Lines per part:")
    spin_lbl.pack(side="left")
    spin = tk.Spinbox(spin_holder, from_=SPLIT_MIN, to=SPLIT_MAX,
                      increment=500, textvariable=split_val, width=10)
    spin.pack(side="left", padx=6)
    tk.Label(spin_holder, text="(default %d, max %d)" % (DEFAULT_SPLIT_LINES, SPLIT_MAX),
             fg="#888888").pack(side="left")

    gi_check = tk.Checkbutton(root, text="Respect .gitignore (folder mode)",
                              variable=gitignore_on,
                              font=("Segoe UI", 10, "bold"))
    gi_check.grid(row=7, column=0, sticky="w", padx=pad_x, pady=(8, 0))
    gi_note = tk.Label(root,
                       text=("On = skip any file or folder that .gitignore would\n"
                             "exclude (honors nested .gitignore files, negation,\n"
                             "and anchoring). Always skips .git/."),
                       fg="#555555", justify="left")
    gi_note.grid(row=8, column=0, sticky="w", padx=pad_x + 22, pady=(2, 4))

    def on_ok():
        if split_on.get():
            try:
                v = int(split_val.get())
            except ValueError:
                messagebox.showerror("Invalid", "Lines per part must be a whole number.")
                return
            if v < SPLIT_MIN or v > SPLIT_MAX:
                messagebox.showerror(
                    "Out of range",
                    "Lines per part must be between %d and %d." % (SPLIT_MIN, SPLIT_MAX))
                return
        choice["ok"] = True
        root.quit()

    def on_cancel():
        choice["ok"] = False
        root.quit()

    btns = tk.Frame(root)
    btns.grid(row=9, column=0, sticky="e", padx=pad_x, pady=12)
    tk.Button(btns, text="OK", width=10, command=on_ok).pack(side="right", padx=(6, 0))
    tk.Button(btns, text="Cancel", width=10, command=on_cancel).pack(side="right")

    root.protocol("WM_DELETE_WINDOW", on_cancel)
    root.bind("<Return>", lambda e: on_ok())
    root.bind("<Escape>", lambda e: on_cancel())

    sync()

    # Force the window to actually appear, on top, with focus. On some
    # Windows setups the window can otherwise open off-screen or behind
    # other windows, which looks exactly like the program "hanging".
    root.update_idletasks()
    w = max(root.winfo_reqwidth(), 480)
    h = max(root.winfo_reqheight(), 300)
    x = (root.winfo_screenwidth() - w) // 2
    y = (root.winfo_screenheight() - h) // 3
    root.geometry("%dx%d+%d+%d" % (w, h, x, y))
    root.deiconify()
    root.lift()
    root.focus_force()
    root.attributes("-topmost", True)
    root.update()
    root.attributes("-topmost", False)

    root.mainloop()

    if not choice["ok"]:
        try:
            root.destroy()
        except Exception:
            pass
        return

    chosen_mode = mode.get()
    split_lines = int(split_val.get()) if split_on.get() else None
    want_gitignore = bool(gitignore_on.get())

    root.withdraw()

    def report(out_paths, count, what):
        if len(out_paths) == 1:
            where = str(out_paths[0])
        else:
            where = ("%d parts:\n  " % len(out_paths)
                     + "\n  ".join(p.name for p in out_paths)
                     + "\n\nin: %s" % out_paths[0].parent)
        messagebox.showinfo(
            "Done",
            "Wrote %d files (%s) to:\n%s\n\n"
            "Excluded by extension: %s\n"
            "Also skipped Intel HEX / Motorola S-Record content."
            % (count, what, where, ", ".join(sorted(ALWAYS_EXCLUDE_EXTS))))

    if chosen_mode == "main":
        filetypes = [
            ("Script files", "*.atsb *.py *.ps1 *.vb *.vbs *.bas *.cls *.frm *.cmd *.bat *.sh *.psm1 *.psd1"),
            ("All files", "*.*"),
        ]
        main_file = filedialog.askopenfilename(title="Select main script file",
                                               filetypes=filetypes)
        if not main_file:
            root.destroy()
            return
        out_file = filedialog.asksaveasfilename(
            title="Save combined file as", defaultextension=".txt",
            initialfile=Path(main_file).with_suffix(".txt").name,
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not out_file:
            root.destroy()
            return
        try:
            count, written = combine_from_main_file_mode(
                main_file=Path(main_file), output_file=Path(out_file),
                max_bytes=None, split_lines=split_lines)
            report(written, count, "main + referenced")
        except Exception as e:
            messagebox.showerror("Error", "Failed: %s" % e)
    else:
        root_dir = filedialog.askdirectory(title="Select root folder to scan")
        if not root_dir:
            root.destroy()
            return
        out_file = filedialog.asksaveasfilename(
            title="Save combined file as", defaultextension=".txt",
            initialfile="combined.txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not out_file:
            root.destroy()
            return
        try:
            count, written = combine_folder_mode(
                root_dir=Path(root_dir), output_file=Path(out_file),
                exclude_dirs=None, max_bytes=None, split_lines=split_lines,
                use_gitignore=want_gitignore)
            report(written, count, "folder mode")
        except Exception as e:
            messagebox.showerror("Error", "Failed: %s" % e)

    try:
        root.destroy()
    except Exception:
        pass


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except BaseException as e:
        import traceback
        tb = traceback.format_exc()
        sys.stderr.write(tb)
        try:
            import tkinter as _tk
            from tkinter import messagebox as _mb
            _r = _tk.Tk(); _r.withdraw()
            _mb.showerror("Code-2-TXT - Startup Error", "%s: %s\n\n%s" % (type(e).__name__, e, tb))
            _r.destroy()
        except Exception:
            pass
        sys.exit(1)