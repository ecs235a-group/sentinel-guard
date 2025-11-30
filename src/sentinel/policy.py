from dataclasses import dataclass
from typing import Any
import yaml


@dataclass
class ValidatorDef:
    id: str
    type: str
    params: dict[str, Any]


@dataclass
class Policy:
    version: int
    defaults: dict[str, Any]
    validators: dict[str, ValidatorDef]


def _parse_validators(items: list[dict[str, Any]]) -> dict[str, ValidatorDef]:
    out: dict[str, ValidatorDef] = {}
    for it in items:
        vid = it.get("id")
        vtype = it.get("type")
        params = {k: v for k, v in it.items() if k not in ("id", "type")}
        if not vid or not vtype:
            raise ValueError("validator missing id or type")
        out[vid] = ValidatorDef(id=vid, type=vtype, params=params)
    return out


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    version = int(data.get("version", 1))
    defaults = data.get("defaults", {})
    validators = _parse_validators(data.get("validators", []))
    return Policy(version=version, defaults=defaults, validators=validators)
