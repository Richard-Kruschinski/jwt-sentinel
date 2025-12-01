import json
from datetime import datetime, timezone

import jwt
from dataclasses import asdict

from .model import AnalysisResult, Finding
from .utils import b64url_decode, to_int


class JwtAnalyzer:
    def __init__(self, config):
        self.config = config

    def analyze(self, token, secret=None):
        header, payload = self._decode_header_and_payload(token)

        findings = []

        algorithm = header.get("alg")

        self._check_algorithm(header, findings)
        self._check_claims(payload, findings)
        self._check_secret_strength(header, secret, findings)
        signature_valid = self._try_verify_signature(token, header, secret, findings)

        score = self._compute_score(findings)

        result = AnalysisResult(
            token=token,
            header=header,
            payload=payload,
            algorithm=algorithm,
            signature_valid=signature_valid,
            findings=findings,
            score=score,
        )

        return result

    # -------------------------------------------------------
    # Helper methods
    # -------------------------------------------------------

    def _decode_header_and_payload(self, token):
        parts = token.split(".")

        if len(parts) < 2:
            raise ValueError("Token does not look like a JWT (needs at least 2 parts).")

        header_part = parts[0]
        payload_part = parts[1]

        try:
            header_bytes = b64url_decode(header_part)
            payload_bytes = b64url_decode(payload_part)

            header_text = header_bytes.decode("utf-8")
            payload_text = payload_bytes.decode("utf-8")

            header = json.loads(header_text)
            payload = json.loads(payload_text)
        except Exception as exc:
            message = "Failed to decode JWT header/payload: {}".format(exc)
            raise ValueError(message)

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise ValueError("Header and payload must be JSON objects (dicts).")

        return header, payload

    def _check_algorithm(self, header, findings):
        alg = header.get("alg")
        typ = header.get("typ")

        forbidden = self.config.get("forbidden_algorithms", [])
        discouraged = self.config.get("discouraged_algorithms", [])
        recommended = self.config.get("recommended_algorithms", [])

        if alg is None:
            finding = Finding(
                id="missing_alg",
                title="Missing 'alg' header",
                severity="medium",
                description="The JWT header does not contain an 'alg' field.",
                recommendation="Always set a concrete, secure algorithm.",
            )
            findings.append(finding)
            return

        if alg in forbidden:
            finding = Finding(
                id="forbidden_alg",
                title="Use of forbidden algorithm '{}'".format(alg),
                severity="high",
                description=(
                    "The token uses '{}', which is considered insecure. "
                    "For example 'none' disables signature verification."
                ).format(alg),
                recommendation="Use RS256 or ES256 instead.",
            )
            findings.append(finding)
        elif alg in discouraged:
            finding = Finding(
                id="discouraged_alg",
                title="Use of discouraged algorithm '{}'".format(alg),
                severity="medium",
                description=(
                    "The token uses '{}'. Symmetric algorithms require careful key management "
                    "and may be vulnerable to key reuse and algorithm confusion."
                ).format(alg),
                recommendation="Prefer asymmetric algorithms and rotate keys regularly.",
            )
            findings.append(finding)
        else:
            if len(recommended) > 0 and alg not in recommended:
                finding = Finding(
                    id="unrecognized_alg",
                    title="Unrecognized algorithm '{}'".format(alg),
                    severity="low",
                    description=(
                        "The algorithm '{}' is neither in the list of recommended nor "
                        "discouraged algorithms."
                    ).format(alg),
                    recommendation="Check if this algorithm is secure in your environment.",
                )
                findings.append(finding)

        if typ is not None:
            typ_upper = str(typ).upper()
            if typ_upper != "JWT":
                finding = Finding(
                    id="unexpected_typ",
                    title="Unexpected 'typ' header: '{}'".format(typ),
                    severity="low",
                    description="The 'typ' header is not 'JWT'. This may be unusual.",
                    recommendation="Make sure the 'typ' header matches your expectations.",
                )
                findings.append(finding)

    def _check_claims(self, payload, findings):
        now = datetime.now(timezone.utc)

        exp_raw = payload.get("exp")
        iat_raw = payload.get("iat")
        nbf_raw = payload.get("nbf")

        exp = to_int(exp_raw)
        iat = to_int(iat_raw)
        nbf = to_int(nbf_raw)

        # exp
        if exp is None:
            finding = Finding(
                id="missing_exp",
                title="Missing 'exp' claim",
                severity="high",
                description=(
                    "The token does not contain an 'exp' claim. Such tokens "
                    "can be valid forever."
                ),
                recommendation="Always include an 'exp' claim with a short lifetime.",
            )
            findings.append(finding)
        else:
            exp_dt = datetime.fromtimestamp(exp, tz=timezone.utc)
            if exp_dt < now:
                finding = Finding(
                    id="expired_token",
                    title="Token has already expired",
                    severity="medium",
                    description="The 'exp' claim is in the past.",
                    recommendation="Reject expired tokens and refresh them.",
                )
                findings.append(finding)

        # long lifetime
        max_lifetime = self.config.get("max_token_lifetime_seconds", 8 * 60 * 60)
        max_lifetime = int(max_lifetime)

        if exp is not None and iat is not None:
            lifetime = exp - iat
            if lifetime > max_lifetime:
                finding = Finding(
                    id="long_lifetime",
                    title="Token lifetime is unusually long",
                    severity="medium",
                    description=(
                        "The token lifetime (exp - iat) is {} seconds, which is longer "
                        "than the configured maximum of {} seconds."
                    ).format(lifetime, max_lifetime),
                    recommendation="Reduce token lifetimes and use refresh tokens.",
                )
                findings.append(finding)

        # nbf in the future
        if nbf is not None:
            nbf_dt = datetime.fromtimestamp(nbf, tz=timezone.utc)
            if nbf_dt > now:
                finding = Finding(
                    id="not_yet_valid",
                    title="Token is not yet valid",
                    severity="low",
                    description="The 'nbf' claim is in the future.",
                    recommendation="Reject tokens before their 'nbf' time.",
                )
                findings.append(finding)

        # presence of iss, sub, aud
        standard_claims = ["iss", "sub", "aud"]
        for claim in standard_claims:
            if claim not in payload:
                finding = Finding(
                    id="missing_{}".format(claim),
                    title="Missing '{}' claim".format(claim),
                    severity="low",
                    description="The token does not contain the '{}' claim.".format(claim),
                    recommendation=(
                        "Include standard claims ('iss', 'sub', 'aud') to make tokens "
                        "easier to validate and debug."
                    ),
                )
                findings.append(finding)

    def _check_secret_strength(self, header, secret, findings):
        alg = header.get("alg")

        if not isinstance(alg, str):
            return

        if alg.startswith("HS"):
            # symmetric (HMAC) algorithm
            if not secret:
                finding = Finding(
                    id="missing_secret",
                    title="No secret provided for symmetric algorithm",
                    severity="medium",
                    description=(
                        "The token uses a symmetric HMAC algorithm, but no secret was given "
                        "to verify the signature."
                    ),
                    recommendation="Use a strong random secret and verify signatures.",
                )
                findings.append(finding)
                return

            min_len = self.config.get("min_secret_length_bytes", 16)
            min_len = int(min_len)

            secret_bytes = secret.encode("utf-8")
            if len(secret_bytes) < min_len:
                finding = Finding(
                    id="weak_secret",
                    title="Secret/key is probably too short",
                    severity="high",
                    description=(
                        "The secret length is shorter than the configured minimum "
                        "({} bytes)."
                    ).format(min_len),
                    recommendation="Use a long, randomly generated secret (at least 128 bits).",
                )
                findings.append(finding)
        else:
            # asymmetric algorithm (RS/ES/...); usually needs a public key
            if not secret:
                finding = Finding(
                    id="no_key_for_asymmetric",
                    title="No verification key provided for asymmetric algorithm",
                    severity="low",
                    description=(
                        "The token uses an asymmetric algorithm, but no key was provided "
                        "for verification."
                    ),
                    recommendation="Provide the public key if you want to verify the signature.",
                )
                findings.append(finding)

    def _try_verify_signature(self, token, header, secret, findings):
        alg = header.get("alg")

        if alg is None:
            return None

        if alg == "none":
            return None

        if not secret:
            return None

        try:
            options = {"verify_exp": False}
            algorithms = [alg]

            jwt.decode(
                token,
                key=secret,
                algorithms=algorithms,
                options=options,
            )
            return True
        except jwt.InvalidSignatureError:
            finding = Finding(
                id="invalid_signature",
                title="Signature verification failed",
                severity="high",
                description="The signature could not be verified with the provided key/secret.",
                recommendation="Check the key and reject tampered tokens.",
            )
            findings.append(finding)
            return False
        except Exception as exc:
            finding = Finding(
                id="verification_error",
                title="Error during signature verification",
                severity="medium",
                description="An error occurred while verifying the signature: {}".format(exc),
                recommendation="Check the key format and algorithm configuration.",
            )
            findings.append(finding)
            return None

    def _compute_score(self, findings):
        base_score = 100

        penalties = {
            "low": 5,
            "medium": 15,
            "high": 30,
        }

        score = base_score

        for finding in findings:
            severity = finding.severity.lower()
            if severity in penalties:
                penalty = penalties[severity]
            else:
                penalty = 0
            score = score - penalty

        if score < 0:
            score = 0
        if score > 100:
            score = 100

        return score


def result_to_json_dict(result):
    """
    Convert AnalysisResult into a normal dict that can be dumped as JSON.
    Uses dataclasses.asdict so we don't have to do it by hand.
    """
    data = asdict(result)
    return data
