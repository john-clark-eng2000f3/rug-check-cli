import argparse
import json
import os
import sys
from pathlib import Path

from rugcheck.parser import parse_target
from rugcheck.pypi import PyPIClient
from rugcheck.rules import evaluate_package

SEVERITY_RANKS = {
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}


def _format_terminal(results, verbose=False):
    # Quick ANSI colors without pulling in colorama
    use_color = sys.stdout.isatty() and not os.getenv("NO_COLOR")
    c_red = "\033[31m" if use_color else ""
    c_yellow = "\033[33m" if use_color else ""
    c_green = "\033[32m" if use_color else ""
    c_dim = "\033[2m" if use_color else ""
    c_reset = "\033[0m" if use_color else ""

    for item in results:
        name = item["package"]
        ver = item["version"] or "any"
        findings = item["findings"]

        if not item["found"]:
            print(f"{c_red}[MISSING]{c_reset} {name} - not found on PyPI or network failed")
            continue

        if not findings:
            if verbose:
                print(f"{c_green}[OK]{c_reset} {name}=={ver}")
            continue

        highest = max((SEVERITY_RANKS.get(f["severity"], 1) for f in findings), default=1)
        tag_color = c_red if highest >= 3 else c_yellow
        tag_label = "DANGER" if highest >= 4 else ("WARN" if highest >= 2 else "INFO")

        print(f"{tag_color}[{tag_label}]{c_reset} {name} ({ver})")
        for f in findings:
            sev = f["severity"].upper()
            print(f"  {c_dim}->{c_reset} [{sev}] {f['code']}: {f['message']}")
            if f.get("detail") and verbose:
                print(f"     {c_dim}{f['detail']}{c_reset}")


def main(argv=None) -> int:
    """Run CLI scanner over specified files or package names."""
    parser = argparse.ArgumentParser(
        prog="rugcheck",
        description="Inspect python packages for supply-chain red flags before running pip.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Requirements file, poetry.lock, Pipfile.lock, or package name(s)",
    )
    parser.add_argument(
        "--fail-on",
        choices=["low", "medium", "high", "critical"],
        default="medium",
        help="Minimum severity level to trigger a non-zero exit code (default: medium)",
    )
    parser.add_argument(
        "--ignore",
        metavar="RULE_CODE",
        action="append",
        default=[],
        help="Ignore specific rule codes (e.g. --ignore RC004)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON findings instead of human readable text",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Show passed checks and extra metadata",
    )

    args = parser.parse_args(argv)
    client = PyPIClient()
    ignored = set(args.ignore)
    threshold = SEVERITY_RANKS[args.fail_on]

    # FIXME: handle cases where requirements.txt points to -r other.txt recursively
    parsed_packages = []
    for target_arg in args.targets:
        target_path = Path(target_arg)
        if target_path.exists() and target_path.is_file():
            parsed_packages.extend(parse_target(target_path))
        else:
            # Single raw package name or specifier string from CLI
            parsed_packages.append((target_arg, None))

    if not parsed_packages:
        if not args.json:
            print("No dependencies found to check.", file=sys.stderr)
        return 0

    results = []
    should_fail = False

    for pkg_name, pinned_ver in parsed_packages:
        meta = client.fetch_package_metadata(pkg_name)
        if not meta:
            results.append({
                "package": pkg_name,
                "version": pinned_ver,
                "found": False,
                "findings": [],
            })
            should_fail = True
            continue

        findings = evaluate_package(meta, pinned_version=pinned_ver)
        filtered = [f for f in findings if f.code not in ignored]

        for f in filtered:
            if SEVERITY_RANKS.get(f.severity, 1) >= threshold:
                should_fail = True

        results.append({
            "package": pkg_name,
            "version": pinned_ver,
            "found": True,
            "findings": [
                {
                    "code": f.code,
                    "severity": f.severity,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in filtered
            ],
        })

    # print(f"DEBUG: evaluated {len(results)} packages")

    if args.json:
        print(json.dumps({"results": results, "failed": should_fail}, indent=2))
    else:
        _format_terminal(results, verbose=args.verbose)

    # Exit code 1 means dangerous findings above threshold
    return 1 if should_fail else 0
