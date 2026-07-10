import pytest
from rugcheck.rules import check_typosquatting, levenshtein


def test_levenshtein_basics():
    assert levenshtein("", "") == 0
    assert levenshtein("requests", "requests") == 0
    assert levenshtein("reqeusts", "requests") == 2
    assert levenshtein("urllib4", "urllib3") == 1
    assert levenshtein("boto", "boto3") == 1


