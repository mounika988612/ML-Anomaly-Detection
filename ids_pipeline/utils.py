import logging
import os
import random
import re
from pathlib import Path

import numpy as np
import torch
import yaml

ROOT = Path(__file__).resolve().parents[1]

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")
_PATH_KEYS = {("paths", "raw_dir"), ("paths", "work_dir"), ("paths", "results_dir"),
              ("report", "capture_dir"), ("data", "suricata_parquet"), ("data", "unsw_dir")}
# (section, key, type) that every pipeline run needs; checked up front so a typo fails with a clear message
_REQUIRED = {
    "paths": ["raw_dir", "work_dir", "results_dir"],
    "data": ["seed", "train_days", "test_days", "val_fraction", "clip"],
    "model": ["hidden", "modality_dim", "latent_dim", "role_dim", "proj_dim", "mask_ratio",
              "modality_dropout", "contrastive_weight", "temperature", "epochs", "batch_size", "lr",
              "weight_decay", "patience"],
    "scoring": ["target_fpr", "xmodal_weight", "min_role_samples"],
}


class ConfigError(ValueError):
    """The configuration file is missing, malformed or incomplete."""


def _expand(value):
    """${VAR} / ${VAR:-default} substitution from the environment (recursive over lists and dicts)."""
    if isinstance(value, str):
        def sub(m):
            v = os.environ.get(m.group(1), m.group(2))
            if v is None:
                raise ConfigError(f"environment variable {m.group(1)} is not set and has no default")
            return v
        return _ENV.sub(sub, value)
    if isinstance(value, list):
        return [_expand(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    return value


def validate_config(cfg):
    for sec, keys in _REQUIRED.items():
        if not isinstance(cfg.get(sec), dict):
            raise ConfigError(f"config section '{sec}' is missing")
        missing = [k for k in keys if k not in cfg[sec]]
        if missing:
            raise ConfigError(f"config section '{sec}' is missing keys: {', '.join(missing)}")
    d, s = cfg["data"], cfg["scoring"]
    if not d["train_days"] or not d["test_days"]:
        raise ConfigError("data.train_days and data.test_days must be non-empty")
    if set(d["train_days"]) & set(d["test_days"]):
        raise ConfigError("data.train_days and data.test_days overlap (test leakage)")
    if not 0 < d["val_fraction"] < 1:
        raise ConfigError("data.val_fraction must be in (0, 1)")
    if not 0 < s["target_fpr"] < 1:
        raise ConfigError("scoring.target_fpr must be in (0, 1)")
    return cfg


def load_config(path=None):
    """Load a YAML config. `${VAR:-default}` is expanded from the environment and every path is
    resolved relative to the config file, so no absolute machine-specific path is needed.
    Output directories are created; input directories are only checked when a stage reads them."""
    path = Path(path or ROOT / "config.yaml")
    if not path.is_file():
        raise ConfigError(f"config file not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            cfg = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigError(f"{path}: invalid YAML: {e}") from e
    if not isinstance(cfg, dict):
        raise ConfigError(f"{path}: expected a mapping at the top level")
    cfg = _expand(cfg)
    validate_config(cfg)
    for sec, key in _PATH_KEYS:
        v = cfg.get(sec, {}).get(key)
        if v:
            p = Path(v).expanduser()
            cfg[sec][key] = p if p.is_absolute() else (path.parent / p).resolve()
    for k in ("work_dir", "results_dir"):
        cfg["paths"][k].mkdir(parents=True, exist_ok=True)
    return cfg


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def get_logger(name="ids"):
    log = logging.getLogger(name)
    if not log.handlers:
        h = logging.StreamHandler()
        h.setFormatter(logging.Formatter("%(asctime)s | %(message)s", "%H:%M:%S"))
        log.addHandler(h)
        log.setLevel(os.environ.get("IDS_LOG_LEVEL", "INFO").upper())
    return log
