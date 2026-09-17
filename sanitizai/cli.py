"""
SanitizAI - Command Line Interface
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Terminal utility for redacting PII and exposed secrets from files,
piped standard input streams, or direct strings.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from sanitizai import __version__
from sanitizai.core import SanitizAI


def build_parser() -> argparse.ArgumentParser:
    """Build the command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sanitizai",
        description=(
            "SanitizAI: Lightning-fast, zero-overhead local PII & secrets redaction "
            "for prompts, logs, and storage."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Sanitize a direct string:
  sanitizai "Contact me at alice@example.com or use key sk-1234567890abcdef1234567890"

  # Stream logs through pipe:
  cat production.log | sanitizai > sanitized.log

  # Sanitize a file to an output file:
  sanitizai -i user_data.txt -o cleaned_data.txt

  # Mask with custom blacklist and print redaction statistics:
  sanitizai --blacklist "ProjectApollo,TopSecret" --stats "Discussing ProjectApollo with sk-abc..."
""",
    )

    parser.add_argument(
        "text",
        nargs="?",
        default=None,
        help="Input text string to sanitize (omit to read from STDIN or input file)",
    )
    parser.add_argument(
        "-i",
        "--input",
        dest="input_file",
        type=Path,
        default=None,
        help="Path to input file to sanitize",
    )
    parser.add_argument(
        "-o",
        "--output",
        dest="output_file",
        type=Path,
        default=None,
        help="Path to output file for sanitized text (defaults to STDOUT)",
    )
    parser.add_argument(
        "--no-pii",
        action="store_true",
        help="Disable PII redaction (email, phone, cards, Aadhaar, PAN, etc.)",
    )
    parser.add_argument(
        "--no-secrets",
        action="store_true",
        help="Disable secret keys & credentials redaction",
    )
    parser.add_argument(
        "--blacklist",
        type=str,
        default="",
        help="Comma-separated list of custom words or phrases to redact",
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="Print summary of detected and redacted entities to STDERR",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show program version and exit",
    )

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Execute the CLI application."""
    parser = build_parser()
    args = parser.parse_args(argv)

    blacklist_words = (
        [w.strip() for w in args.blacklist.split(",") if w.strip()]
        if args.blacklist
        else []
    )

    sanitizer = SanitizAI(
        mask_pii=not args.no_pii,
        mask_secrets=not args.no_secrets,
        blacklist_words=blacklist_words,
    )

    total_stats = {}

    # Case 1: Direct text argument
    if args.text is not None:
        if args.stats:
            total_stats = sanitizer.analyze(args.text)

        cleaned = sanitizer.clean(args.text)
        if args.output_file:
            args.output_file.write_text(cleaned, encoding="utf-8")
        else:
            sys.stdout.write(cleaned + "\n")

    # Case 2: Input file
    elif args.input_file is not None:
        if not args.input_file.exists():
            sys.stderr.write(f"Error: Input file '{args.input_file}' does not exist.\n")
            return 1

        content = args.input_file.read_text(encoding="utf-8", errors="replace")
        if args.stats:
            total_stats = sanitizer.analyze(content)

        cleaned = sanitizer.clean(content)
        if args.output_file:
            args.output_file.write_text(cleaned, encoding="utf-8")
        else:
            sys.stdout.write(cleaned)

    # Case 3: Piped STDIN stream
    else:
        # Check if stdin has data or is interactive
        if sys.stdin.isatty():
            # Interactive prompt
            sys.stderr.write("SanitizAI: Reading from STDIN. Press Ctrl+D (or Ctrl+Z on Windows) to end.\n")

        out_handle = (
            args.output_file.open("w", encoding="utf-8")
            if args.output_file
            else sys.stdout
        )

        try:
            for line in sys.stdin:
                if args.stats:
                    line_stats = sanitizer.analyze(line)
                    for k, v in line_stats.items():
                        total_stats[k] = total_stats.get(k, 0) + v
                out_handle.write(sanitizer.clean(line))
        finally:
            if args.output_file:
                out_handle.close()

    # Print stats to stderr if requested
    if args.stats:
        sys.stderr.write("\n--- SanitizAI Redaction Summary ---\n")
        if total_stats:
            for entity, count in sorted(total_stats.items()):
                sys.stderr.write(f"  {entity}: {count}\n")
            sys.stderr.write(f"  Total Redactions: {sum(total_stats.values())}\n")
        else:
            sys.stderr.write("  No sensitive entities detected.\n")
        sys.stderr.write("-----------------------------------\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
