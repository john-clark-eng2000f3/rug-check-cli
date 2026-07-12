import pytest
from rugcheck.rules import check_typosquatting, levenshtein


def test_levenshtein_basics():
    assert levenshtein("", "") == 0
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("reqeusts", "requests") == 2
    assert levenshtein("urllib4", "urllib3") == 1
    assert levenshtein("boto", "boto3") == 1


def test_typosquat_direct_hit():
    # shouldn't flag exact matches as squats of themselves
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
