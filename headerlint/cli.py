import argparse
import json
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
    parser.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="output format (default: text)",
    )
    args = parser.parse_args(argv)

    exit_code = 0
    json_results = []
    for path in args.paths:
        try:
            text = _read(path)
        except OSError as exc:
            print(f"{path}: {exc.strerror}", file=sys.stderr)
            exit_code = 2
            continue

        label = "<stdin>" if path == "-" else path
        findings = lint_text(text)
        for finding in findings:
            if finding.severity == "error":
                exit_code = max(exit_code, 1)

        if args.format == "json":
            json_results.append(
                {
                    "file": label,
                    "findings": [
                        {
                            "line": f.line,
                            "severity": f.severity,
                            "code": f.code,
                            "message": f.message,
                        }
                        for f in findings
                    ],
                }
            )
        else:
            for finding in findings:
                print(
                    f"{label}:{finding.line}: {finding.severity} "
                    f"{finding.code} {finding.message}"
                )

    if args.format == "json":
        print(json.dumps(json_results, indent=2))

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
