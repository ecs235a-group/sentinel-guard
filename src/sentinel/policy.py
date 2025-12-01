from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Optional
import yaml


@dataclass
class ValidatorDef:
    id: str
    type: str
    params: dict[str, Any]


@dataclass
class SinkDef:
    id: str
    function: str
    require: list[str] = field(default_factory=list)
    on_violation: dict[str, Any] = field(default_factory=dict)
    forbid_functions: list[str] = field(default_factory=list)


@dataclass
class Policy:
    version: int
    defaults: dict[str, Any]
    sources: list[dict[str, Any]]
    validators: dict[str, ValidatorDef]
    sinks: dict[str, SinkDef]
    flows: list[dict[str, Any]] = field(default_factory=list)
    secrets: list[dict[str, Any]] = field(default_factory=list)

    def get_sink_for_function(self, func_fqn: str) -> Optional[SinkDef]:
        # direct match
        for _, s in self.sinks.items():
            if s.function == func_fqn:
                return s
        return None


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


def _parse_sinks(items: list[dict[str, Any]]) -> dict[str, SinkDef]:
    out: dict[str, SinkDef] = {}
    for it in items:
        sid = it.get("id")
        require = it.get("require", []) or []
        on_violation = it.get("on_violation", {}) or {}
        forbid_functions = it.get("forbid_functions", []) or []
        out[sid] = SinkDef(
            id=sid,
            function=it.get("function"),
            require=require,
            on_violation=on_violation,
            forbid_functions=forbid_functions,
        )
    return out


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    version = data.get("version", 1)
    defaults = data.get("defaults", {})
    sources = data.get("sources", []) or []
    validators = _parse_validators(data.get("validators", []) or [])
    sinks = _parse_sinks(data.get("sinks", []) or [])
    flows = data.get("flows", []) or []
    secrets = data.get("secrets", []) or []
    return Policy(
        version=version,
        defaults=defaults,
        sources=sources,
        validators=validators,
        sinks=sinks,
        flows=flows,
        secrets=secrets,
    )
