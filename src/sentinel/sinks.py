from __future__ import annotations
import builtins
import subprocess
import os
import yaml
import sqlite3
from typing import Iterable
from functools import wraps
from pathlib import Path

from .policy import Policy
from .validators import validate_value
from .logging_utils import log

# Import taint_flow from middleware 
try:
    from .middleware import taint_flow
except ImportError:
    taint_flow = None

import string

try:
    import jinja2

    HAS_JINJA2 = True
except ImportError:
    HAS_JINJA2 = False

try:
    import requests

    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import urllib.request

    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

# Save originals
_ORIG = {
    "open": builtins.open,
    "subprocess.run": subprocess.run,
    "os.system": os.system,
    "yaml.load": yaml.load,
    "yaml.safe_load": yaml.safe_load,
    "sqlite3.connect": sqlite3.connect,
}


class PolicyViolation(Exception):
    pass


def _strings_from_args(*args, **kwargs) -> Iterable[str]:
    # Extract string-like values to validate
    for a in args:
        if isinstance(a, (str, bytes)):
            yield a.decode() if isinstance(a, bytes) else a
        elif isinstance(a, (list, tuple)):
            for x in a:
                if isinstance(x, (str, bytes)):
                    yield x.decode() if isinstance(x, bytes) else x
    for v in kwargs.values():
        if isinstance(v, (str, bytes)):
            yield v.decode() if isinstance(v, bytes) else v
        elif isinstance(v, (list, tuple)):
            for x in v:
                if isinstance(x, (str, bytes)):
                    yield x.decode() if isinstance(x, bytes) else x


def _get_flow() -> list:
    """Return a copy of the current taint flow list, or [] if unavailable."""
    if taint_flow is None:
        return []
    try:
        return list(taint_flow.get())
    except Exception:
        return []


def _record_flowpoint(name: str) -> None:
    """Record that tainted data reached `name` (non-fatal if unavailable)."""
    if taint_flow is None:
        return
    try:
        stack = taint_flow.get()
        # avoid runaway growth from repeated calls
        if not stack or stack[-1] != name:
            stack.append(name)
            taint_flow.set(stack)
    except Exception:
        pass


def _enforce(policy: Policy, sink_fqn: str, strings: Iterable[str]):
    """
    Backward-compatible enforcement:
    - Same policy decisions as before (block/warn/sanitize)
    - Adds 'taint_flow' to logs if available
    - Safe when middleware/ContextVar is absent (e.g., CLI)
    """
    # provenance marker: data reached this sink
    _record_flowpoint(sink_fqn)

    sink = policy.get_sink_for_function(sink_fqn)
    if not sink:
        return  # no policy for this sink

    # For forbidden functions list, if matched, always block
    if sink.forbid_functions and sink_fqn in sink.forbid_functions:
        log(
            {
                "event": "blocked",
                "sink": sink_fqn,
                "reason": "forbidden function",
                "taint_flow": _get_flow(),
            }
        )
        raise PolicyViolation(f"{sink_fqn} is forbidden by policy")

    # Apply validators (same logic as before)
    for vid in sink.require:
        for s in strings:
            ok, msg = validate_value(policy, vid, s)
            if not ok:
                mode = sink.on_violation.get(
                    "mode", policy.defaults.get("mode", "block")
                )
                message = sink.on_violation.get("message", f"violation {vid}: {msg}")
                log(
                    {
                        "event": "violation",
                        "sink": sink_fqn,
                        "validator": vid,
                        "msg": msg,
                        "mode": mode,
                        "taint_flow": _get_flow(),
                    }
                )
                if mode == "block":
                    raise PolicyViolation(message)
                elif mode == "warn":
                    # allow but log (already logged above)
                    pass
                elif mode == "sanitize":
                    # not implemented (same as before)
                    pass


def apply_patches(policy: Policy):
    """Monkey-patch sinks based on policy."""

    # builtins.open (validate path for write modes)
    @wraps(_ORIG["open"])
    def guarded_open(file, mode="r", *args, **kwargs):
        # Enforce only on write-like modes
        write_like = any(m in mode for m in ("w", "a", "x", "+"))
        if write_like:
            sink = policy.get_sink_for_function("builtins.open")
            if sink:
                p = Path(str(file))
                # Run validators against the correct target:
                # - safe_filename => basename only (no directory separators)
                # - path_in_uploads (and any other path-level checks) => full path
                for vid in sink.require:
                    target = p.name if vid == "safe_filename" else str(p)
                    ok, msg = validate_value(policy, vid, target)
                    if not ok:
                        mode_eff = sink.on_violation.get(
                            "mode", policy.defaults.get("mode", "block")
                        )
                        message = sink.on_violation.get(
                            "message", f"violation {vid}: {msg}"
                        )
                        log(
                            {
                                "event": "violation",
                                "sink": "builtins.open",
                                "validator": vid,
                                "msg": msg,
                                "mode": mode_eff,
                                "basename": p.name,
                                "full_path": str(p),
                                "taint_flow": _get_flow(),
                            }
                        )
                        if mode_eff == "block":
                            raise PolicyViolation(message)
                        # (warn/sanitize branches could be extended here if desired)
        return _ORIG["open"](file, mode, *args, **kwargs)

    builtins.open = guarded_open

    # subprocess.run
    @wraps(_ORIG["subprocess.run"])
    def guarded_run(*args, **kwargs):
        # Validate all strings (command and args).
        strings = list(_strings_from_args(*args, **kwargs))
        _enforce(policy, "subprocess.run", strings)
        return _ORIG["subprocess.run"](*args, **kwargs)

    subprocess.run = guarded_run

    # os.system
    @wraps(_ORIG["os.system"])
    def guarded_system(cmd):
        _enforce(policy, "os.system", [cmd])
        return _ORIG["os.system"](cmd)

    os.system = guarded_system

    # -------- YAML: safe_load and load --------
    # Make safe_load call the ORIGINAL loader with SafeLoader directly,
    # so it never trips the patched yaml.load enforcement.
    @wraps(_ORIG["yaml.safe_load"])
    def guarded_safe_load(stream, *args, **kwargs):
        kwargs.setdefault("Loader", yaml.SafeLoader)
        return _ORIG["yaml.load"](stream, **kwargs)

    yaml.safe_load = guarded_safe_load

    # Forbid raw yaml.load (or downgrade to SafeLoader if policy chooses warn)
    @wraps(_ORIG["yaml.load"])
    def forbidden_yaml_load(*args, **kwargs):
        _enforce(policy, "yaml.load", ["yaml.load"])
        # If not blocked (e.g., warn), force SafeLoader anyway
        kwargs.setdefault("Loader", yaml.SafeLoader)
        return _ORIG["yaml.load"](*args, **kwargs)

    yaml.load = forbidden_yaml_load

    # SQLite protection - wrap connection to return guarded cursors
    @wraps(_ORIG["sqlite3.connect"])
    def guarded_sqlite_connect(*args, **kwargs):
        conn = _ORIG["sqlite3.connect"](*args, **kwargs)

        # Create a wrapper class that inherits from the connection type
        class GuardedConnection:
            def __init__(self, connection):
                self._conn = connection

            def __getattr__(self, name):
                # Delegate all other attributes to the real connection
                return getattr(self._conn, name)

            def cursor(self, *cursor_args, **cursor_kwargs):
                # Get the real cursor
                real_cursor = self._conn.cursor(*cursor_args, **cursor_kwargs)

                # Create a wrapper class for the cursor
                class GuardedCursor:
                    def __init__(self, cursor):
                        self._cursor = cursor

                    def __getattr__(self, name):
                        # Delegate all other attributes to the real cursor
                        return getattr(self._cursor, name)

                    def execute(self, sql, parameters=()):
                        _enforce(policy, "sqlite3.Cursor.execute", [str(sql)])
                        return self._cursor.execute(sql, parameters)

                    def executemany(self, sql, seq_of_parameters):
                        _enforce(policy, "sqlite3.Cursor.executemany", [str(sql)])
                        return self._cursor.executemany(sql, seq_of_parameters)

                return GuardedCursor(real_cursor)

        return GuardedConnection(conn)

    sqlite3.connect = guarded_sqlite_connect

    if HAS_JINJA2:
        _ORIG["jinja2.Template.render"] = jinja2.Template.render

        @wraps(_ORIG["jinja2.Template.render"])
        def guarded_jinja_render(self, *args, **kwargs):
            # Check template content and variables for injection patterns
            template_content = getattr(self, "source", "") or str(self)
            strings_to_check = [template_content]

            # Check template variables
            for arg in args:
                if isinstance(arg, dict):
                    strings_to_check.extend(
                        str(v) for v in arg.values() if isinstance(v, (str, int, float))
                    )
            for v in kwargs.values():
                if isinstance(v, (str, int, float)):
                    strings_to_check.append(str(v))

            _enforce(policy, "jinja2.Template.render", strings_to_check)
            return _ORIG["jinja2.Template.render"](self, *args, **kwargs)

        jinja2.Template.render = guarded_jinja_render

    # String template protection
    _ORIG["string.Template.substitute"] = string.Template.substitute

    @wraps(_ORIG["string.Template.substitute"])
    def guarded_template_substitute(self, *args, **kwargs):
        # Check template content and substitution values
        template_content = self.template
        strings_to_check = [template_content]

        # Check substitution values
        if args and isinstance(args[0], dict):
            strings_to_check.extend(str(v) for v in args[0].values())
        strings_to_check.extend(str(v) for v in kwargs.values())

        _enforce(policy, "string.Template.substitute", strings_to_check)
        return _ORIG["string.Template.substitute"](self, *args, **kwargs)

    string.Template.substitute = guarded_template_substitute

    # SSRF protection
    if HAS_REQUESTS:
        _ORIG["requests.get"] = requests.get
        _ORIG["requests.post"] = requests.post

        @wraps(_ORIG["requests.get"])
        def guarded_requests_get(url, **kwargs):
            _enforce(policy, "requests.get", [str(url)])
            return _ORIG["requests.get"](url, **kwargs)

        @wraps(_ORIG["requests.post"])
        def guarded_requests_post(url, **kwargs):
            _enforce(policy, "requests.post", [str(url)])
            return _ORIG["requests.post"](url, **kwargs)

        requests.get = guarded_requests_get
        requests.post = guarded_requests_post

    if HAS_URLLIB:
        _ORIG["urllib.request.urlopen"] = urllib.request.urlopen

        @wraps(_ORIG["urllib.request.urlopen"])
        def guarded_urlopen(url, **kwargs):
            url_str = str(url) if hasattr(url, "get_full_url") else str(url)
            _enforce(policy, "urllib.request.urlopen", [url_str])
            return _ORIG["urllib.request.urlopen"](url, **kwargs)

        urllib.request.urlopen = guarded_urlopen
