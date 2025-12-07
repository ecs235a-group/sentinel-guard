import re
import json
import unicodedata
from typing import Any
from pathlib import Path
from jsonschema import Draft7Validator, exceptions as jsonschema_exceptions

from .policy import (
    Policy,
    StringValidatorParams,
    PathValidatorParams,
    JsonSchemaValidatorParams,
)

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


def _validate_string(value: Any, params: StringValidatorParams) -> tuple[bool, str]:
    s = str(value)
    s = _normalize_text(s)

    if params.max_len is not None and len(s) > int(params.max_len):
        return False, f"length>{params.max_len}"
    if params.min_len is not None and len(s) < int(params.min_len):
        return False, f"length<{params.min_len}"
    if params.deny_regex and re.search(str(params.deny_regex), s):
        return False, "matches forbidden pattern"
    for sub in params.deny_substrings:
        if sub in s:
            return False, f"contains forbidden substring {sub!r}"

    if params.allow_charset:
        if re.fullmatch(f"^[{params.allow_charset}]+$", s) is None:
            return False, "contains disallowed characters"
    if params.match_regex:
        if re.fullmatch(str(params.match_regex), s) is None:
            return False, "regex mismatch"
    return True, "ok"


def _validate_path(value: Any, params: PathValidatorParams) -> tuple[bool, str]:
    # Enforce path is under allowed directories; optional subdirectories denial
    try:
        path = Path(str(value)).resolve()
    except Exception as e:
        return False, f"path invalid: {e}"

    if not params.allowed_roots:
        return False, "no allowed roots configured"

    for root in params.allowed_roots:
        try:
            root_path = Path(root).resolve()
        except Exception:
            # Skip malformed root entries
            continue

        # Check whether 'path' is under 'root_path'
        try:
            path.relative_to(root_path)
        except Exception:
            # not under this root
            continue

        # If we get here, path is under (or equal to) root_path
        if params.deny_subdirectories and path.parent != root_path:
            return False, f"subdirectories disallowed under {root_path}"
        return True, "ok"

    return False, f"path not under allowed roots: {params.allowed_roots}"


def _validate_json(obj: Any, params: JsonSchemaValidatorParams) -> tuple[bool, str]:
    try:
        validator = _load_schema(params.schema_ref)
        errors = sorted(validator.iter_errors(obj), key=lambda e: list(e.path))
        if errors:
            first = errors[0]
            return False, f"json schema error at {list(first.path)}: {first.message}"
        return True, "ok"
    except jsonschema_exceptions.ValidationError as e:
        return False, f"json schema error: {str(e)}"
    except Exception as e:
        return False, f"json schema load/validate error: {e}"


# Public API
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
