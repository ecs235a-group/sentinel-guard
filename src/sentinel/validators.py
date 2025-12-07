from __future__ import annotations
import re
import json
import unicodedata
from typing import Any
from pathlib import Path
from jsonschema import Draft7Validator, exceptions as jsonschema_exceptions

from .policy import Policy
from .taint import TaintedStr

_schema_cache: dict[str, Draft7Validator] = {}


class ValidationError(Exception):
    pass


def _normalize_text(value: str) -> str:
    try:
        return unicodedata.normalize("NFC", value)
    except Exception:
        return value


def _load_schema(ref: str) -> Draft7Validator:
    if ref in _schema_cache:
        return _schema_cache[ref]
    # Assume local file path
    with open(ref, "r", encoding="utf-8") as f:
        schema = json.load(f)
    v = Draft7Validator(schema)
    _schema_cache[ref] = v
    return v


def _validate_string(value: Any, params: dict[str, Any]) -> tuple[bool, str]:
    s = str(value)
    s = _normalize_text(s)

    max_len = params.get("max_len")
    min_len = params.get("min_len")
    regex = params.get("regex")
    allow_charset = params.get("allow_charset")
    deny_regex = params.get("deny_regex")
    deny_substrings = params.get("deny_substrings", [])

    if max_len is not None and len(s) > int(max_len):
        return False, f"length>{max_len}"
    if min_len is not None and len(s) < int(min_len):
        return False, f"length<{min_len}"
    if deny_regex and re.search(str(deny_regex), s):
        return False, "matches forbidden pattern"
    for sub in deny_substrings:
        if sub in s:
            return False, f"contains forbidden substring {sub!r}"

    if allow_charset:
        if re.fullmatch(f"^[{allow_charset}]+$", s) is None:
            return False, "contains disallowed characters"
    if regex:
        if re.fullmatch(str(regex), s) is None:
            return False, "regex mismatch"
    return True, "ok"


def _validate_path(value: Any, params: dict[str, Any]) -> tuple[bool, str]:
    # Enforce path is under allowed directories; optional subdirectories denial
    must_be_under = params.get("must_be_under", [])
    deny_subdirectories = bool(params.get("deny_subdirectories", False))

    try:
        path = Path(str(value)).resolve()
    except Exception as e:
        return False, f"path invalid: {e}"

    if not must_be_under:
        return False, "no allowed roots configured"

    for root in must_be_under:
        try:
            root_path = Path(root).resolve()
        except Exception:
            # Skip malformed root entries
            continue

        # Check whether `path` is under `root_path`
        try:
            path.relative_to(root_path)
        except Exception:
            # not under this root
            continue

        # If we get here, path is under (or equal to) root_path
        if deny_subdirectories and path.parent != root_path:
            return False, f"subdirectories disallowed under {root_path}"
        return True, "ok"

    return False, f"path not under allowed roots: {must_be_under}"


def _validate_json(obj: Any, params: dict[str, Any]) -> tuple[bool, str]:
    ref = params.get("schema_ref")
    if not ref:
        return False, "no schema_ref provided"
    try:
        validator = _load_schema(ref)
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            return False, f"json schema error at {list(first.path)}: {first.message}"
        return True, "ok"
    except jsonschema_exceptions.ValidationError as e:
        return False, f"json schema error: {str(e)}"
    except Exception as e:
        return False, f"json schema load/validate error: {e}"

# Public APIs
def validate_value(policy: Policy, validator_id: str, value: Any) -> tuple[bool, str]:
    vdef = policy.validators.get(validator_id)
    if not vdef:
        return False, f"unknown validator {validator_id}"
    vtype = vdef.type
    params = vdef.params

    if vtype == "string":
        return _validate_string(str(value), params)
    if vtype == "path":
        return _validate_path(str(value), params)
    if vtype == "json_schema":
        return _validate_json(value, params)
    return False, f"unknown validator type {vtype}"


def validate_json_by_id(
    policy: Policy, validator_id: str, obj: Any
) -> tuple[bool, str]:
    return validate_value(policy, validator_id, obj)
