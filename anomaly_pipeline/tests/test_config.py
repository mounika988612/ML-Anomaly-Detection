import copy
from pathlib import Path

import pytest
import yaml

from ids_pipeline.utils import ROOT, ConfigError, load_config, validate_config

BASE = yaml.safe_load((ROOT / "config.yaml").read_text(encoding="utf-8"))


def write(tmp_path, cfg):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg), encoding="utf-8")
    return p


def test_shipped_configs_are_portable_and_valid(tmp_path, monkeypatch):
    for k in ("IDS_DATA_DIR", "IDS_WORK_DIR", "IDS_RESULTS_DIR"):
        monkeypatch.delenv(k, raising=False)
    for f in ROOT.glob("config*.yaml"):
        text = f.read_text(encoding="utf-8")
        assert "D:/" not in text and "/mnt/" not in text, f"{f.name} hard-codes a machine path"
        monkeypatch.setenv("IDS_WORK_DIR", str(tmp_path / f.stem / "w"))
        monkeypatch.setenv("IDS_RESULTS_DIR", str(tmp_path / f.stem / "r"))
        cfg = load_config(f)
        assert cfg["paths"]["raw_dir"].is_absolute()


def test_env_override_and_default(tmp_path, monkeypatch):
    cfg = copy.deepcopy(BASE)
    cfg["paths"] = dict(raw_dir="${IDS_DATA_DIR:-rel/data}", work_dir=str(tmp_path / "w"), results_dir=str(tmp_path / "r"))
    p = write(tmp_path, cfg)
    monkeypatch.delenv("IDS_DATA_DIR", raising=False)
    assert load_config(p)["paths"]["raw_dir"] == (tmp_path / "rel" / "data").resolve()   # relative to the config file
    monkeypatch.setenv("IDS_DATA_DIR", str(tmp_path / "elsewhere"))
    assert load_config(p)["paths"]["raw_dir"] == Path(tmp_path / "elsewhere")


def test_unset_variable_without_default_fails(tmp_path, monkeypatch):
    cfg = copy.deepcopy(BASE)
    cfg["paths"]["raw_dir"] = "${IDS_SURELY_UNSET}"
    monkeypatch.delenv("IDS_SURELY_UNSET", raising=False)
    with pytest.raises(ConfigError, match="IDS_SURELY_UNSET"):
        load_config(write(tmp_path, cfg))


def test_missing_file_and_bad_yaml(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_config(tmp_path / "nope.yaml")
    p = tmp_path / "bad.yaml"
    p.write_text("a: [unclosed", encoding="utf-8")
    with pytest.raises(ConfigError, match="invalid YAML"):
        load_config(p)


@pytest.mark.parametrize("mutate,msg", [
    (lambda c: c.pop("model"), "'model' is missing"),
    (lambda c: c["data"].pop("seed"), "missing keys: seed"),
    (lambda c: c["data"].update(test_days=c["data"]["train_days"]), "overlap"),
    (lambda c: c["data"].update(val_fraction=1.5), "val_fraction"),
    (lambda c: c["scoring"].update(target_fpr=0), "target_fpr"),
])
def test_invalid_configs_are_rejected(mutate, msg):
    cfg = copy.deepcopy(BASE)
    mutate(cfg)
    with pytest.raises(ConfigError, match=msg):
        validate_config(cfg)
