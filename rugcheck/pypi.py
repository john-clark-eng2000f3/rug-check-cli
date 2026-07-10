import json
import time
import urllib.request
import urllib.error
from pathlib import Path

CACHE_DIR = Path.home() / ".cache" / "rugcheck"
CACHE_TTL = 3600 * 6  # 6 hours


class PyPIClient:
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
                pass

        url = f"https://pypi.org/pypi/{norm_name}/json"
        req = urllib.request.Request(url, headers={"User-Agent": "rugcheck/0.1"})
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                cache_file.write_text(json.dumps(data), encoding="utf-8")
                return data
        except urllib.error.HTTPError as err:
            if err.code == 404:
                return None
            raise
        except Exception:
            return None
