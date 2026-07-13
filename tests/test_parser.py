from rugcheck.parser import parse_requirements, parse_poetry_lock, parse_pipfile_lock


def test_parse_simple_requirements(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
    requests==2.31.0
    flask>=2.0.0
    # some comment
    pytest
    urllib3<3.0,>=1.26
    """)

    deps = parse_requirements(req_file)
    names = [d["name"] for d in deps]
    assert "requests" in names
    assert "flask" in names
    assert "pytest" in names
    assert "urllib3" in names
    assert len(deps) == 4


def test_parse_requirements_with_markers_and_flags(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
    tomli==2.0.1; python_version < '3.11'
    black>=23.0.0 # code formatter
    -e git+https://github.com/psf/black.git#egg=black
    --extra-index-url https://download.pytorch.org/whl/cpu
    torch
    """)

    deps = parse_requirements(req_file)
    names = [d["name"] for d in deps]
    assert "tomli" in names
    assert "black" in names
    assert "torch" in names
    # editable git url should be bypassed
    assert len(deps) == 3


def test_parse_poetry_lock(tmp_path):
    lock = tmp_path / "poetry.lock"
    lock.write_text("""
    [[package]]
    name = "httpx"
    version = "0.24.1"
    description = "HTTP client"
    category = "main"
    optional = false
    python-versions = ">=3.7"

    [[package]]
    name = "PyYAML"
    version = "6.0"
    """)

    deps = parse_poetry_lock(lock)
    assert len(deps) == 2
    assert deps[0]["name"] == "httpx"
    assert deps[0]["version"] == "0.24.1"
    assert deps[1]["name"] == "pyyaml"


def test_parse_pipfile_lock(tmp_path):
    lock = tmp_path / "Pipfile.lock"
    lock.write_text("""{
        "_meta": {"hash": {"sha256": "123"}},
        "default": {
            "django": {"version": "==4.2.1"},
            "redis": {"version": "==5.0.0"}
        },
        "develop": {
            "pytest": {"version": "==7.4.0"}
        }
    }""")

    deps = parse_pipfile_lock(lock)
    names = {d["name"] for d in deps}
    assert names == {"django", "redis", "pytest"}
