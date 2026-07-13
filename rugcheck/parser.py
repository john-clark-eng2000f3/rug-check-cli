import json
import re
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib


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
        # ignore nested refs, flags and git/url direct dependencies
        if line.startswith(("-r", "--requirement", "-i", "-e", "--editable", "--index-url", "--extra-index-url")):
            continue
        if "@" in line or "git+" in line or "://" in line:
            continue

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


def parse_pipfile_lock(path):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"pipfile lock not found: {path}")

    data = json.loads(p.read_text(encoding="utf-8"))
    deps = []
    sections = [data.get("default", {}), data.get("develop", {})]
    for sec in sections:
        for name, details in sec.items():
            norm_name = name.lower().replace("_", "-")
            ver = ""
            if isinstance(details, dict):
                ver = details.get("version", "").lstrip("=")
            deps.append({"name": norm_name, "version": ver, "file": str(p)})
    return deps


def extract_dependencies(target_path):
    """Detect file format and return normalized dependency items."""
    p = Path(target_path)
    name = p.name.lower()
    if name == "poetry.lock":
        return parse_poetry_lock(p)
    elif name in ("pipfile.lock", "pipfile.frozen"):
        return parse_pipfile_lock(p)
    return parse_requirements(p)
