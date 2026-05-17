"""Command line interface for logveil."""

from __future__ import annotations

import argparse
import gzip
import os
import sys
from pathlib import Path
from typing import BinaryIO, TextIO

from .anonymizer import MailLogAnonymizer


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="logveil",
        description="Anonymize existing mail server log files while preserving statistical value.",
    )
    parser.add_argument("input", help="Input log file. Gzip is supported when the name ends in .gz.")
    parser.add_argument("output", help="Output log file. Ignored when --dry-run is used.")
    parser.add_argument("--key-file", required=True, help="Path to the HMAC key file.")
    parser.add_argument(
        "--preserve-email-domain",
        action="store_true",
        help="Keep email domains while anonymizing the local part.",
    )
    parser.add_argument(
        "--preserve-ip-prefix",
        action="store_true",
        help="Reserved for future subnet-preserving IP anonymization.",
    )
    parser.add_argument("--dry-run", action="store_true", help="Write anonymized output to stdout.")
    parser.add_argument("--stats", action="store_true", help="Print replacement counts to stderr.")
    parser.add_argument("--verbose", action="store_true", help="Print progress information to stderr.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.preserve_ip_prefix:
        parser.error("--preserve-ip-prefix is not supported yet")

    input_path = Path(args.input)
    output_path = Path(args.output)

    if _same_path(input_path, output_path):
        parser.error("OUTPUT must be different from INPUT")

    key = load_or_create_key(Path(args.key_file), verbose=args.verbose)
    anonymizer = MailLogAnonymizer(key, preserve_email_domain=args.preserve_email_domain)

    if args.verbose:
        print(f"Reading {input_path}", file=sys.stderr)

    line_count = 0
    if args.dry_run:
        with open_input(input_path) as input_file:
            line_count = process_stream(input_file, sys.stdout, anonymizer)
    else:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open_input(input_path) as input_file, output_path.open(
            "w", encoding="utf-8", errors="replace", newline=""
        ) as output_file:
            line_count = process_stream(input_file, output_file, anonymizer)

    if args.verbose:
        destination = "stdout" if args.dry_run else str(output_path)
        print(f"Wrote {line_count} lines to {destination}", file=sys.stderr)

    if args.stats:
        print_stats(anonymizer, line_count)

    return 0


def load_or_create_key(path: Path, verbose: bool = False) -> bytes:
    if path.exists():
        key = path.read_bytes()
        if not key:
            raise SystemExit("Key file is empty")
        return key

    path.parent.mkdir(parents=True, exist_ok=True)
    key = os.urandom(32)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as key_file:
            key_file.write(key)
    except Exception:
        try:
            path.unlink()
        finally:
            raise

    try:
        os.chmod(path, 0o600)
    except OSError:
        pass

    if verbose:
        print(f"Created key file {path}", file=sys.stderr)
    return key


def open_input(path: Path) -> TextIO:
    if path.name.endswith(".gz"):
        binary_file: BinaryIO = gzip.open(path, "rb")
        return _wrap_binary_text(binary_file)
    return path.open("r", encoding="utf-8", errors="replace", newline="")


def _wrap_binary_text(binary_file: BinaryIO) -> TextIO:
    import io

    return io.TextIOWrapper(binary_file, encoding="utf-8", errors="replace", newline="")


def process_stream(input_file: TextIO, output_file: TextIO, anonymizer: MailLogAnonymizer) -> int:
    count = 0
    for line in input_file:
        output_file.write(anonymizer.anonymize_line(line))
        count += 1
    return count


def print_stats(anonymizer: MailLogAnonymizer, line_count: int) -> None:
    print(f"lines={line_count}", file=sys.stderr)
    for name in ("email", "ip", "host", "user", "msgid"):
        print(f"{name}={anonymizer.stats.get(name, 0)}", file=sys.stderr)


def _same_path(first: Path, second: Path) -> bool:
    try:
        return first.resolve() == second.resolve()
    except OSError:
        return os.path.abspath(first) == os.path.abspath(second)


if __name__ == "__main__":
    raise SystemExit(main())
