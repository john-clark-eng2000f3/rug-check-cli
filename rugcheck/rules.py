import ast
import difflib
from datetime import datetime, timezone

POPULAR_PACKAGES = [
    "requests", "urllib3", "typing-extensions", "setuptools", "wheel",
    "pip", "certifi", "idna", "charset-normalizer", "six", "pytest",
    "click", "numpy", "pandas", "boto3", "botocore", "cryptography",
    "pydantic", "flask", "django", "torch", "scipy", "pillow", "pyyaml",
    "fastapi", "jinja2", "werkzeug", "sqlalchemy", "attrs", "rich",
    "aiohttp", "asyncpg", "psycopg2", "black", "flake8", "alembic",
    "tqdm", "pyjwt", "redis", "celery", "httpx", "uvicorn", "gunicorn",
]

SUSPICIOUS_CALLS = {
    "exec", "eval", "__import__", "compile",
    "subprocess.Popen", "subprocess.run", "subprocess.call", "subprocess.check_output",
    "os.system", "os.popen", "os.spawnlp",
    "urllib.request.urlopen", "requests.get", "requests.post", "socket.connect",
    "base64.b64decode",
}


def check_typosquatting(name):
    norm = name.lower().replace("_", "-")
    if norm in POPULAR_PACKAGES:
        return None

    # check direct distance and character swaps like reqeusts vs requests
    matches = difflib.get_close_matches(norm, POPULAR_PACKAGES, n=1, cutoff=0.83)
    if matches:
        target = matches[0]
        if abs(len(norm) - len(target)) <= 2 and norm != target:
            return f"Possible typosquatting of '{target}'"
    return None


def check_metadata_anomalies(meta, target_version=""):
    issues = []
    info = meta.get("info", {})
    releases = meta.get("releases", {})

    # 1. yanked release check
    if info.get("yanked"):
        reason = info.get("yanked_reason") or "no reason specified"
        issues.append(f"Latest release is yanked: {reason}")

    if target_version and target_version in releases:
        files = releases[target_version]
        if any(f.get("yanked", False) for f in files):
            issues.append(f"Version {target_version} was yanked by maintainer")

    # 2. upstream repo verification
    home = (info.get("home_page") or "").strip()
    proj_urls = info.get("project_urls") or {}
    combined_urls = [home] + list(proj_urls.values())

    has_source = False
    for raw in combined_urls:
        if not raw:
            continue
        u = raw.lower()
        if any(host in u for host in ["github.com/", "gitlab.com/", "bitbucket.org/", "codeberg.org/"]):
            has_source = True
            break
    if not has_source:
        issues.append("No repository link declared in package metadata")

    # 3. age check (brand new releases under 72h can be risky)
    urls = meta.get("urls", [])
    if urls:
        upload_str = urls[0].get("upload_time_iso_8601")
        if upload_str:
            try:
                # python 3.11 handle 'Z'
                dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600.0
                if age_hours < 72:
                    issues.append(f"Very fresh upload ({age_hours:.1f} hours old)")
            except Exception:
                pass

    # print(f"debug: checked {info.get('name')} -> {len(issues)} flags")
    return issues


class _SuspiciousCallVisitor(ast.NodeVisitor):
    def __init__(self):
        self.found = []

    def visit_Call(self, node):
        name = ""
        if isinstance(node.func, ast.Name):
            name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                name = f"{node.func.value.id}.{node.func.attr}"
            else:
                name = node.func.attr

        if name in SUSPICIOUS_CALLS:
            self.found.append(name)
        self.generic_visit(node)


def analyze_setup_script(script_content):
    """Looks for network calls, system shells, or obfuscated execution inside setup.py."""
    if not script_content:
        return []

    findings = []
    try:
        tree = ast.parse(script_content)
    except SyntaxError:
        return ["Unparseable setup.py syntax (possible custom payload)"]

    visitor = _SuspiciousCallVisitor()
    visitor.visit(tree)

    for call_name in sorted(set(visitor.found)):
        findings.append(f"Suspicious build-time call detected: '{call_name}()'")

    # quick string heuristic for b64 blob runs
    if "base64.b64decode" in script_content and "exec(" in script_content:
        findings.append("Detected b64decode combined with exec in setup script")

    return findings
