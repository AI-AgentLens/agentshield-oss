#!/usr/bin/env python3
"""
Remove DROPped compliance controls from all taxonomy YAML entry files.

DROPped controls:
  eu-ai-act-2024: Art.9, Art.26
  soc2-type2:     CC8.1, CC9.1
  iso-27001-2022: A.5.1, A.8.26, A.8.33
"""

import os
import re
import sys
from pathlib import Path

# Map of standard -> set of controls to remove
DROPPED = {
    "eu-ai-act-2024": {"Art.9", "Art.26"},
    "soc2-type2":     {"CC8.1", "CC9.1"},
    "iso-27001-2022": {"A.5.1", "A.8.26", "A.8.33"},
    "mitre_atlas":    {"AML.T0017", "AML.T0031", "AML.T0043", "AML.T0015",
                       "AML.T0036", "AML.T0040", "AML.T0009", "AML.T0016",
                       "AML.T0050", "AML.T0046"},
}

# Files to skip (not entry files)
SKIP_FILES = {"_kingdom.yaml", "kingdoms.yaml", "mcp-known-servers.yaml"}


def remove_control_from_array_string(array_str: str, controls_to_remove: set) -> str | None:
    """
    Given an inline YAML array string like '["Art.9", "Art.15"]' or
    "['Art.9', 'Art.15']", remove any controls in controls_to_remove.
    Returns the new array string, or None if array becomes empty.
    Preserves the original quote style (double or single).
    """
    # Detect quote style: single or double
    single_quoted = re.search(r"'([^']+)'", array_str)
    double_quoted = re.search(r'"([^"]+)"', array_str)

    if single_quoted and not double_quoted:
        items = re.findall(r"'([^']+)'", array_str)
        remaining = [item for item in items if item not in controls_to_remove]
        if not remaining:
            return None
        return '[' + ', '.join(f"'{item}'" for item in remaining) + ']'
    else:
        items = re.findall(r'"([^"]+)"', array_str)
        remaining = [item for item in items if item not in controls_to_remove]
        if not remaining:
            return None
        return '[' + ', '.join(f'"{item}"' for item in remaining) + ']'


def process_file(filepath: Path, stats: dict) -> bool:
    """
    Process a single YAML file. Returns True if the file was modified.
    """
    content = filepath.read_text(encoding="utf-8")
    lines = content.splitlines(keepends=True)
    new_lines = []
    modified = False

    for line in lines:
        kept = line
        for standard, controls_to_drop in DROPPED.items():
            # Match a compliance line for this standard:
            # e.g.   iso-27001-2022: ["A.5.1", "A.8.12"]
            # Leading whitespace + standard + : + array
            pattern = r'^(\s+' + re.escape(standard) + r':\s*)(\[.*\])([ \t]*)(\n?)$'
            m = re.match(pattern, kept)
            if m:
                prefix, array_str, trailing, newline = m.groups()
                new_array = remove_control_from_array_string(array_str, controls_to_drop)
                all_items = set(re.findall(r'"([^"]+)"', array_str)) | set(re.findall(r"'([^']+)'", array_str))
                removed = all_items & controls_to_drop
                if removed:
                    modified = True
                    # Track stats
                    for ctrl in removed:
                        key = f"{standard}:{ctrl}"
                        stats["per_control"][key] = stats["per_control"].get(key, 0) + 1
                    if new_array is None:
                        # Entire line should be removed
                        kept = None
                    else:
                        kept = prefix + new_array + trailing + newline
                break  # Only one standard per line

        if kept is not None:
            new_lines.append(kept)

    if modified:
        filepath.write_text("".join(new_lines), encoding="utf-8")
        stats["files_modified"] += 1
        return True
    return False


def main():
    repo_root = Path(__file__).parent.parent
    taxonomy_dir = repo_root / "taxonomy"

    if not taxonomy_dir.exists():
        print(f"ERROR: taxonomy directory not found at {taxonomy_dir}", file=sys.stderr)
        sys.exit(1)

    stats = {
        "files_scanned": 0,
        "files_modified": 0,
        "per_control": {},
    }

    yaml_files = [
        p for p in taxonomy_dir.rglob("*.yaml")
        if p.name not in SKIP_FILES
    ]

    for filepath in sorted(yaml_files):
        stats["files_scanned"] += 1
        process_file(filepath, stats)

    print(f"Files scanned:  {stats['files_scanned']}")
    print(f"Files modified: {stats['files_modified']}")
    print()
    print("Controls removed per standard:control:")
    total = 0
    for standard in DROPPED:
        for ctrl in sorted(DROPPED[standard]):
            key = f"{standard}:{ctrl}"
            count = stats["per_control"].get(key, 0)
            total += count
            if count:
                print(f"  {key:45s}  {count:4d} occurrences removed")
            else:
                print(f"  {key:45s}  (none found)")
    print(f"\nTotal control occurrences removed: {total}")


if __name__ == "__main__":
    main()
