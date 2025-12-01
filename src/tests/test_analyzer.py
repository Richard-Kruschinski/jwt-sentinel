import time

import jwt

from jwt_sentinel.analyzer import JwtAnalyzer
from jwt_sentinel.config import DEFAULT_CONFIG


def make_analyzer():
    config_copy = DEFAULT_CONFIG.copy()
    analyzer = JwtAnalyzer(config_copy)
    return analyzer


def test_missing_exp_claim_is_detected():
    analyzer = make_analyzer()

    payload = {
        "sub": "alice",
        # no exp
    }

    token = jwt.encode(payload, key="secret", algorithm="HS256")

    result = analyzer.analyze(token, secret="secret")

    finding_ids = []
    for f in result.findings:
        finding_ids.append(f.id)

    assert "missing_exp" in finding_ids
    assert result.score < 100


def test_long_lifetime_is_penalized():
    analyzer = make_analyzer()

    now = int(time.time())
    max_lifetime = DEFAULT_CONFIG["max_token_lifetime_seconds"]

    payload = {
        "sub": "alice",
        "iat": now,
        "exp": now + max_lifetime * 2,
    }

    token = jwt.encode(payload, key="strong-secret-value", algorithm="HS256")

    result = analyzer.analyze(token, secret="strong-secret-value")

    finding_ids = []
    for f in result.findings:
        finding_ids.append(f.id)

    assert "long_lifetime" in finding_ids
    assert result.score < 100
