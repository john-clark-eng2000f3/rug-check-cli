from rugcheck.parser import parse_requirements


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


def test_parse_requirements_with_markers(tmp_path):
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
    tomli==2.0.1; python_version < '3.11'
    black>=23.0.0 # code formatter
    --extra-index-url https://download.pytorch.org/whl/cpu
    torch
    """)

    deps = parse_requirements(req_file)
    names = [d["name"] for d in deps]
    assert "tomli" in names
    assert "black" in names
    assert "torch" in names
    assert "--extra-index-url" not in names
