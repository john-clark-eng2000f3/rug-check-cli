import pytest
from rugcheck.rules import (
    check_typosquatting,
    levenshtein,
    compute_risk_score,
    evaluate_package,
    Finding,
    Severity,
)


def test_levenshtein_basics():
    assert levenshtein("", "") == 0
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("reqeusts", "requests") == 2
    assert levenshtein("urllib4", "urllib3") == 1
    assert levenshtein("boto", "boto3") == 1


def test_levenshtein_case_and_separators():
    # pypi treats - and _ identically, caller usually normalizes
    # but distance func itself is dumb on purpose
    assert levenshtein("python-dateutil", "python_dateutil") == 1


def test_typosquat_direct_hit():
    popular = ["requests", "flask", "urllib3", "pydantic"]
    squats = check_typosquatting("requests", popular)
    assert len(squats) == 0


def test_typosquat_catches_close_names():
    popular = ["requests", "flask", "urllib3", "pydantic"]
    
    hits = check_typosquatting("reqeusts", popular, max_distance=2)
    assert len(hits) == 1
    assert hits[0].target == "requests"
    assert hits[0].distance == 2

    hits_sub = check_typosquatting("urllib4", popular, max_distance=1)
    assert len(hits_sub) == 1
    assert hits_sub[0].target == "urllib3"


def test_typosquat_skips_distant_names():
    popular = ["requests", "flask", "urllib3"]
    hits = check_typosquatting("completely-random-pkg-xyz", popular, max_distance=2)
    assert len(hits) == 0


def test_typosquat_short_name_guard():
    # 2-letter packages like 'id' or 're' shouldn't match everything with dist <= 2
    popular = ["id", "ip", "os", "requests"]
    hits = check_typosquatting("ox", popular, max_distance=2)
    # distance is 1, but length ratio guard should kick in
    assert len(hits) == 0


def test_compute_risk_score_weights():
    findings = [
        Finding(rule="typosquat", severity=Severity.HIGH, message="looks like requests"),
        Finding(rule="yanked", severity=Severity.CRITICAL, message="release was yanked"),
    ]
    score = compute_risk_score(findings)
    # critical (40) + high (25) = 65
    assert score == 65


def test_compute_risk_score_capped_at_100():
    findings = [
        Finding(rule="r1", severity=Severity.CRITICAL, message="boom"),
        Finding(rule="r2", severity=Severity.CRITICAL, message="boom"),
        Finding(rule="r3", severity=Severity.CRITICAL, message="boom"),
    ]
    assert compute_risk_score(findings) == 100


def test_evaluate_package_clean():
    meta = {
        "name": "requests",
        "version": "2.31.0",
        "yanked": False,
        "project_urls": {"Source": "https://github.com/psf/requests"},
        "has_install_hooks": False,
    }
    findings = evaluate_package(meta, popular_names=["requests", "flask"])
    # print("findings:", findings)
    assert len(findings) == 0


def test_evaluate_package_suspicious_combo():
    meta = {
        "name": "reqeusts",
        "version": "0.1.0",
        "yanked": True,
        "yanked_reason": "security issue",
        "project_urls": {},
        "has_install_hooks": True,
    }
    findings = evaluate_package(meta, popular_names=["requests", "flask"])
    rules_fired = {f.rule for f in findings}
    assert "typosquat" in rules_fired
    assert "yanked" in rules_fired
    assert "no_source_repo" in rules_fired
    assert "install_hook" in rules_fired
