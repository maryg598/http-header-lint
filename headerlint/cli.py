import argparse
import sys

from . import lint_text


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="headerlint",
        description="Lint a raw HTTP header block and report findings with line numbers.",
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["-"],
        help="files to lint (omit, or pass -, to read from stdin)",
    )
    args = parser.parse_args(argv)

    exit_code = 0
    for path in args.paths:
        try:
            text = _read(path)
        except OSError as exc:
            print(f"{path}: {exc.strerror}", file=sys.stderr)
            exit_code = 2
            continue

        label = "<stdin>" if path == "-" else path
        for finding in lint_text(text):
            print(f"{label}:{finding.line}: {finding.severity} {finding.code} {finding.message}")
            if finding.severity == "error":
                exit_code = max(exit_code, 1)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
