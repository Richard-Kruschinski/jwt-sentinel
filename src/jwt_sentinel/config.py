import json
from pathlib import Path


DEFAULT_CONFIG = {
    "max_token_lifetime_seconds": 8 * 60 * 60,  # 8 hours
    "min_secret_length_bytes": 16,
    "recommended_algorithms": ["RS256", "ES256"],
    "discouraged_algorithms": ["HS256"],
    "forbidden_algorithms": ["none"],
}


def load_config(path):
    """
    Load JSON config file and override DEFAULT_CONFIG.
    If no path is given, just return the defaults.
    """
    config = DEFAULT_CONFIG.copy()

    if path is None:
        return config

    cfg_path = Path(path)

    if not cfg_path.is_file():
        raise FileNotFoundError("Config file not found: {}".format(cfg_path))

    with cfg_path.open("r", encoding="utf-8") as f:
        user_cfg = json.load(f)

    if not isinstance(user_cfg, dict):
        raise ValueError("Config file must contain a JSON object at the root")

    for key, value in user_cfg.items():
        config[key] = value

    return config
