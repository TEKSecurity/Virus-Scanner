#!/usr/bin/env python3
import os
import sys
import time
import argparse
from datetime import datetime

from modules.file_scan import scan_directory  # uses your module


HASH_FILE_DEFAULT = os.path.join("hashes", "bad_hashes.txt")
REPORT_DIR_DEFAULT = "reports"


def load_hashes(path: str) -> set[str]:
    """
    Loads SHA-256 hashes from a text file.
    - One hash per line
    - Ignores blank lines
    - Ignores comments starting with '#'
    """
    bad = set()
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            bad.add(line.lower())
    return bad


def count_files(directory: str) -> int:
    """Counts files for nicer progress output (best-effort)."""
    total = 0
    for _, _, files in os.walk(directory):
        total += len(files)
    return total


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_report(report_path: str, content: str) -> None:
    ensure_dir(os.path.dirname(report_path))
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description="TEK Security - Endpoint Hash Scanner (Windows-friendly v1)")
    parser.add_argument(
        "--hashes",
        default=HASH_FILE_DEFAULT,
        help=f"Path to bad hashes file (default: {HASH_FILE_DEFAULT})"
    )
    parser.add_argument(
        "--target",
        action="append",
        help="Directory to scan. Use multiple --target args to scan multiple folders."
    )
    parser.add_argument(
        "--report-dir",
        default=REPORT_DIR_DEFAULT,
        help=f"Report output directory (default: {REPORT_DIR_DEFAULT})"
    )
    parser.add_argument(
        "--no-count",
        action="store_true",
        help="Skip pre-counting files (faster startup, less accurate progress)."
    )
    args = parser.parse_args()

    # Default target if none provided
    targets = args.target if args.target else [os.path.expandvars(r"%USERPROFILE%\Downloads")]

    # Validate hash file
    if not os.path.exists(args.hashes):
        print(f"[X] Hash file not found: {args.hashes}")
        print("    Create it at hashes/bad_hashes.txt and add one SHA-256 per line.")
        return 1

    # Load hashes
    bad_hashes = load_hashes(args.hashes)
    if not bad_hashes:
        print("[!] Warning: Your bad hash list is empty. Add some hashes first.")
    else:
        print(f"[+] Loaded {len(bad_hashes):,} bad hashes from: {args.hashes}")

    # Start scan
    start_time = time.time()
    scan_time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    total_files = None
    if not args.no_count:
        try:
            total_files = sum(count_files(t) for t in targets if os.path.exists(t))
        except Exception:
            total_files = None  # best-effort

    print("\nTEK Security - Scan Starting")
    print("--------------------------------")
    print(f"Start time: {scan_time_str}")
    print("Targets:")
    for t in targets:
        print(f" - {t}")
    print("--------------------------------\n")

    all_hits: list[str] = []
    scanned_targets: list[str] = []

    # Note: scan_directory currently does its own os.walk.
    # We'll show progress by printing per-target start/finish + totals.
    # (If you want live per-file progress, see the optional upgrade below.)
    scanned_so_far = 0

    for target in targets:
        if not os.path.exists(target):
            print(f"[!] Skipping missing target: {target}")
            continue

        scanned_targets.append(target)
        print(f"[>] Scanning: {target}")

        # If you skipped counting, we still show basic progress.
        def progress(scanned, path):
            print(f"[scan] {scanned:,} files.. {path}")
        
        hits = scan_directory(target, bad_hashes, on_progress=progress)
        all_hits.extend(hits)

        # Rough progress update (without per-file hooks)
        if total_files:
            # We can't know exactly how many files scan_directory walked without modifying it,
            # so we approximate by recounting just this target (still okay for v1).
            try:
                scanned_so_far += count_files(target)
                pct = (scanned_so_far / total_files) * 100 if total_files else 0
                print(f"[~] Progress: {scanned_so_far:,}/{total_files:,} files (~{pct:.1f}%)")
            except Exception:
                pass

        print(f"[<] Done: {target} | Hits so far: {len(all_hits)}\n")

    elapsed = time.time() - start_time

    # Build report
    report_lines = []
    report_lines.append("TEK Security – Endpoint Scan Report")
    report_lines.append("----------------------------------")
    report_lines.append(f"Scan started: {scan_time_str}")
    report_lines.append(f"Elapsed: {elapsed:.1f} seconds")
    report_lines.append("")
    report_lines.append("Targets scanned:")
    for t in scanned_targets:
        report_lines.append(f" - {t}")
    report_lines.append("")
    report_lines.append(f"Bad hashes loaded: {len(bad_hashes):,}")
    report_lines.append(f"Matches found: {len(all_hits):,}")
    report_lines.append("")
    report_lines.append("Matches:")
    if all_hits:
        for p in all_hits:
            report_lines.append(f" - {p}")
    else:
        report_lines.append(" - None")
    report_lines.append("")
    report_lines.append("Note: This tool is read-only and does not remove files automatically.")

    report_text = "\n".join(report_lines)

    # Save report
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(args.report_dir, f"scan_report_{timestamp}.txt")
    write_report(report_path, report_text)

    # Print summary
    print("Scan Complete ✅")
    print("--------------------------------")
    print(f"Elapsed: {elapsed:.1f}s")
    print(f"Matches found: {len(all_hits)}")
    print(f"Report saved to: {report_path}")
    if all_hits:
        print("\n[!] REVIEW RECOMMENDED — No action was taken automatically.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
