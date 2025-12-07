from dataclasses import dataclass, field
from enum import Enum
import yaml
from typing import Any


class ViolationMode(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    SANITIZE = "sanitize"


@dataclass
class StringValidatorParams:
    max_len: int | None = None
    min_len: int | None = None
    match_regex: str | None = None
    allow_charset: str | None = None
    deny_regex: str | None = None
    deny_substrings: list[str] = field(default_factory=list)


@dataclass
class PathValidatorParams:
    allowed_roots: list[str] = field(default_factory=list)
    deny_subdirectories: bool = False


@dataclass
class JsonSchemaValidatorParams:
    schema_ref: str


@dataclass
class OnViolationDef:
    mode: ViolationMode
    message: str


@dataclass
class DefaultsDef:
    mode: str


@dataclass
class ValidatorDef:
    id: str
    type: str
    params: StringValidatorParams | PathValidatorParams | JsonSchemaValidatorParams


@dataclass
class SinkDef:
    id: str
    function: str
    require: list[str] = field(default_factory=list)
    on_violation: OnViolationDef | None = None


@dataclass
class Policy:
    version: int
    defaults: DefaultsDef
    validators: dict[str, ValidatorDef]
    sinks: dict[str, SinkDef]

    def get_sink_for_function(self, func_fqn: str) -> SinkDef | None:
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
        params_dict = it.get("params", {})
        if not vid or not vtype:
            raise ValueError("validator missing id or type")
        if not isinstance(params_dict, dict):
            raise ValueError(f"validator '{vid}': params must be a dictionary")

        # Parse params based on validator type
        if vtype == "string":
            params = StringValidatorParams(
                max_len=params_dict.get("max_len"),
                min_len=params_dict.get("min_len"),
                match_regex=params_dict.get("match_regex"),
                allow_charset=params_dict.get("allow_charset"),
                deny_regex=params_dict.get("deny_regex"),
                deny_substrings=params_dict.get("deny_substrings", []),
            )
        elif vtype == "path":
            params = PathValidatorParams(
                allowed_roots=params_dict.get("allowed_roots", []),
                deny_subdirectories=bool(params_dict.get("deny_subdirectories", False)),
            )
        elif vtype == "json_schema":
            schema_ref = params_dict.get("schema_ref")
            if not schema_ref:
                raise ValueError(f"validator '{vid}': json_schema requires schema_ref")
            params = JsonSchemaValidatorParams(schema_ref=schema_ref)
        else:
            raise ValueError(f"validator '{vid}': unknown validator type '{vtype}'")

        out[vid] = ValidatorDef(id=vid, type=vtype, params=params)
    return out


def _parse_sinks(items: list[dict[str, Any]]) -> dict[str, SinkDef]:
    out: dict[str, SinkDef] = {}
    for item in items:
        sid = item.get("id")
        require = item.get("require", [])
        on_violation_dict = item.get("on_violation", {})

        # Parse on_violation if present
        on_violation = None
        if on_violation_dict:
            mode_str = on_violation_dict.get("mode")
            mode = None
            if mode_str:
                try:
                    mode = ViolationMode(mode_str.lower())
                except ValueError:
                    raise ValueError(
                        f"sink '{sid}': invalid mode '{mode_str}'. "
                        f"Must be one of: {[m.value for m in ViolationMode]}"
                    )
            on_violation = OnViolationDef(
                mode=mode,
                message=on_violation_dict.get("message"),
            )

        out[sid] = SinkDef(
            id=sid,
            function=item.get("function"),
            require=require,
            on_violation=on_violation,
        )
    return out


def load_policy(path: str) -> Policy:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    version = data.get("version", 1)
    defaults = DefaultsDef(mode=data.get("defaults", {}).get("mode"))
    validators = _parse_validators(data.get("validators", []))
    sinks = _parse_sinks(data.get("sinks", []))
    return Policy(
        version=version,
        defaults=defaults,
        validators=validators,
        sinks=sinks,
    )
