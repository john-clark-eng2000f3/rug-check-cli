import difflib
from datetime import datetime, timezone

POPULAR_PACKAGES = [
    "requests", "urllib3", "typing-extensions", "setuptools", "wheel",
    "pip", "certifi", "idna", "charset-normalizer", "six", "pytest",
    "click", "numpy", "pandas", "boto3", "botocore", "cryptography",
    "pydantic", "flask", "django", "torch", "scipy", "pillow", "pyyaml",
    "fastapi", "jinja2", "werkzeug", "sqlalchemy", "attrs", "rich",
]


def check_typosquatting(name):
    if name in POPULAR_PACKAGES:
        return None
    matches = difflib.get_close_matches(name, POPULAR_PACKAGES, n=1, cutoff=0.82)
    if matches:
        target = matches[0]
        # ignore obvious distinct names that happen to have close score
        if len(name) > 3 and target != name:
            return f"Possible typosquatting of popular package '{target}' (target: '{name}')"
    return None


def check_missing_repo(info):
    home = (info.get("home_page") or "").strip()
    project_urls = info.get("project_urls") or {}
    urls = [home] + list(project_urls.values())
    
    has_repo = False
    for u in urls:
        if not u:
            continue
        u_lower = u.lower()
        if "github.com/" in u_lower or "gitlab.com/" in u_lower or "bitbucket.org/" in u_lower:
            has_repo = True
            break

    if not has_repo:
        return "No upstream repository found (no GitHub/GitLab/Bitbucket URL in metadata)"
    return None
