import argparse
import sys
from pathlib import Path

from rugcheck.parser import parse_target
from rugcheck.pypi import PyPIClient
from rugcheck.rules import evaluate_package


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="rugcheck",
        description="Check python packages for supply-chain risks before pip install.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="Package names, requirement strings, or paths to requirements/lock files",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Print extra details"
    )

    args = parser.parse_args(argv)
    client = PyPIClient()

    packages = []
    for target in args.targets:
        target_path = Path(target)
        if target_path.exists() and target_path.is_file():
            packages.extend(parse_target(target_path))
        else:
            # Treat as single raw requirement or package name
            packages.append((target, None))

    if not packages:
        print("No packages found to inspect.", file=sys.stderr)
        return 0

    has_warnings = False
    for pkg_name, pinned_ver in packages:
        info = client.fetch_package_metadata(pkg_name)
        if not info:
            print(f"[-] {pkg_name}: not found on PyPI")
            has_warnings = True
            continue

        findings = evaluate_package(info, pinned_version=pinned_ver)
        if findings:
            has_warnings = True
            print(f"[!] {pkg_name} ({pinned_ver or 'any'}):")
            for finding in findings:
                print(f"    - [{finding.severity.upper()}] {finding.code}: {finding.message}")
        elif args.verbose:
            print(f"[+] {pkg_name}: ok")

    return 1 if has_warnings else 0
