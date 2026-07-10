import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # python < 3.11


REQ_LINE_RE = re.compile(
    r"^([a-zA-Z0-9_.-]+)\s*(?:([=><~!^]{1,2})\s*([a-zA-Z0-9_.*+-]+))?"
)


def parse_requirements(path):
    deps = []
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"requirements file not found: {path}")

    for raw_line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement", "-i", "--index-url", "--extra-index-url")):
            # skip nested files and flags for now
            continue

        # drop inline comments and environment markers
        clean = line.split(";")[0].split("#")[0].strip()
        m = REQ_LINE_RE.match(clean)
        if m:
            name = m.group(1).lower().replace("_", "-")
            spec = m.group(2) or ""
            ver = m.group(3) or ""
            deps.append({"name": name, "version": f"{spec}{ver}".strip(), "file": str(p)})
    return deps


def parse_poetry_lock(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"poetry lock not found: {path}")

    data = tomllib.loads(p.read_text(encoding="utf-8"))
    deps = []
    for pkg in data.get("package", []):
        name = pkg.get("name", "").lower().replace("_", "-")
        ver = pkg.get("version", "")
        if name:
            deps.append({"name": name, "version": ver, "file": str(p)})
    return deps
