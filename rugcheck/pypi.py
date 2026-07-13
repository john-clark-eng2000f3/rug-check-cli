import io
import json
import tarfile
import time
import urllib.error
import urllib.request
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "rugcheck"
CACHE_TTL = 3600 * 12
MAX_TARBALL_BYTES = 1024 * 1024 * 4  # max 4MB to avoid memory abuse on huge sdists


class PyPIClient:
    """Fetches release metadata and reads setup scripts from PyPI sdists."""

    def __init__(self, cache_dir=None):
        self.cache_dir = Path(cache_dir) if cache_dir else CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get_metadata(self, package_name):
        norm_name = package_name.strip().lower().replace("_", "-")
        cache_file = self.cache_dir / f"{norm_name}.json"

        if cache_file.exists():
            try:
                mtime = cache_file.stat().st_mtime
                if time.time() - mtime < CACHE_TTL:
                    return json.loads(cache_file.read_text(encoding="utf-8"))
            except Exception:
                # broken cache json, fetch fresh
                pass

        url = f"https://pypi.org/pypi/{norm_name}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "rugcheck/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=12) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                try:
                    cache_file.write_text(json.dumps(data), encoding="utf-8")
                except OSError:
                    pass
                return data
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            return None
        except Exception:
            return None

    def fetch_setup_script(self, sdist_url):
        if not sdist_url or not (sdist_url.endswith(".tar.gz") or sdist_url.endswith(".tgz")):
            return None

        req = urllib.request.Request(sdist_url, headers={"User-Agent": "rugcheck/0.2"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                # read only up to limit to prevent zip bombs
                raw = resp.read(MAX_TARBALL_BYTES + 1)
                if len(raw) > MAX_TARBALL_BYTES:
                    return None

                with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        base = Path(member.name).name
                        if base in ("setup.py", "setup.cfg") and member.isfile():
                            f = tar.extractfile(member)
                            if f:
                                return f.read().decode("utf-8", errors="ignore")
        except Exception:
            return None
        return None
