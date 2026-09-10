# rug-check-cli

CLI scanner to spot supply-chain red flags in Python lockfiles and requirements before running `pip install` or bumping lockfiles.

I got tired of manually opening PyPI tabs every time an indirect dependency bumped major versions with zero release notes or came from an account created three days ago. This script checks PyPI metadata and package tarballs against a few simple heuristics.

## Install

```bash
pip install .
# or with pipx
pipx install .
```

## Usage

Check a requirements file or lockfile:
```bash
rugcheck requirements.txt
rugcheck poetry.lock
```

Inspect a single package directly from PyPI:
```bash
rugcheck --pkg some-suspicious-pkg
```

Fail CI on high severity flags:
```bash
rugcheck requirements.txt --min-score 70 --quiet
```

## What it looks for

- Package age vs release velocity (brand new accounts pushing releases on high-traffic names)
- Typosquatting distance against popular packages
- Tarball inspection for suspicious build-time hooks (`setup.py` / `build.py` calling subprocess or raw sockets)
- Yanked release spikes and mismatched repository metadata

## License

MIT

<!-- generated: 2026-09-10 -->
