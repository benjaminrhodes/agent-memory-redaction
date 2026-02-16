"""CLI interface."""

import argparse
import sys
from src.redactor import Redactor, PIIType


def main():
    parser = argparse.ArgumentParser(description="Redact PII from text")
    parser.add_argument(
        "--pii-types",
        nargs="+",
        choices=[t.value for t in PIIType],
        help="PII types to redact (default: all)",
    )
    parser.add_argument(
        "input",
        nargs="?",
        help="Input text to redact (if not provided, reads from stdin)",
    )
    args = parser.parse_args()

    pii_types = None
    if args.pii_types:
        pii_types = [PIIType(t) for t in args.pii_types]

    redactor = Redactor(pii_types=pii_types)

    if args.input:
        text = args.input
    else:
        text = sys.stdin.read()

    result = redactor.redact(text)
    print(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
