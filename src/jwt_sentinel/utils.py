import base64


def b64url_decode(segment):
    """
    Decode base64url without padding. JWT uses this format.
    """
    missing = (-len(segment)) % 4
    padding = "=" * missing
    fixed_segment = segment + padding
    decoded = base64.urlsafe_b64decode(fixed_segment)
    return decoded


def to_int(value):
    """
    Try to convert a value to int. Return None if it fails.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
