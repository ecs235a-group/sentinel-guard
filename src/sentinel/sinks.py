import builtins
import subprocess
import os
import yaml
import sqlite3
import string
from functools import wraps
from pathlib import Path

from .policy import Policy, ViolationMode
from .validators import validate_value
from .logging_utils import log
from .middleware import taint_flow


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


def _strings_from_args(*args, **kwargs) -> list[str]:
    # Extract string-like values to validate
    result = []
    for a in args:
        if isinstance(a, (str, bytes)):
            result.append(a.decode() if isinstance(a, bytes) else a)
        elif isinstance(a, (list, tuple)):
            for x in a:
                if isinstance(x, (str, bytes)):
                    result.append(x.decode() if isinstance(x, bytes) else x)
    for v in kwargs.values():
        if isinstance(v, (str, bytes)):
            result.append(v.decode() if isinstance(v, bytes) else v)
        elif isinstance(v, (list, tuple)):
            for x in v:
                if isinstance(x, (str, bytes)):
                    result.append(x.decode() if isinstance(x, bytes) else x)
    return result


def _get_flow() -> list:
    """Return a copy of the current taint flow list, or [] if unavailable."""
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


def _enforce(policy: Policy, sink_fqn: str, strings: list[str]):
    """
    Enforce policy validation on strings passed to a sink function.

    Applies validators from the sink's policy definition and handles violations
    according to the configured mode (block/warn/sanitize). Includes taint flow
    tracking in logs when available (works in both web and CLI contexts).
    """
    # provenance marker: data reached this sink
    _record_flowpoint(sink_fqn)

    sink = policy.get_sink_for_function(sink_fqn)
    if not sink:
        return  # no policy for this sink

    # Apply validators
    for vid in sink.require:
        for s in strings:
            ok, msg = validate_value(policy, vid, s)
            if not ok:
                if sink.on_violation and sink.on_violation.mode:
                    mode = sink.on_violation.mode
                else:
                    default_mode_str = policy.defaults.mode or "block"
                    try:
                        mode = ViolationMode(default_mode_str.lower())
                    except ValueError:
                        mode = ViolationMode.BLOCK  # fallback to block
                message = (
                    sink.on_violation.message
                    if sink.on_violation and sink.on_violation.message
                    else f"violation {vid}: {msg}"
                )
                log(
                    {
                        "event": "violation",
                        "sink": sink_fqn,
                        "validator": vid,
                        "msg": msg,
                        "mode": mode.value,
                        "taint_flow": _get_flow(),
                    }
                )
                if mode == ViolationMode.BLOCK:
                    raise PolicyViolation(message)
                elif mode == ViolationMode.WARN:
                    # allow but log (already logged above)
                    pass
                elif mode == ViolationMode.SANITIZE:
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
                # Allow Python bytecode cache files (.pyc) and __pycache__ directories
                # These are internal Python operations and shouldn't be blocked
                if "__pycache__" in p.parts or p.suffix == ".pyc":
                    return _ORIG["open"](file, mode, *args, **kwargs)

                # Run validators against the correct target:
                # - safe_filename => basename only (no directory separators)
                # - path_in_uploads (and any other path-level checks) => full path
                for vid in sink.require:
                    target = p.name if vid == "safe_filename" else str(p)
                    ok, msg = validate_value(policy, vid, target)
                    if not ok:
                        if sink.on_violation and sink.on_violation.mode:
                            mode_eff = sink.on_violation.mode
                        else:
                            default_mode_str = policy.defaults.mode or "block"
                            try:
                                mode_eff = ViolationMode(default_mode_str.lower())
                            except ValueError:
                                mode_eff = ViolationMode.BLOCK  # fallback to block
                        message = (
                            sink.on_violation.message
                            if sink.on_violation and sink.on_violation.message
                            else f"violation {vid}: {msg}"
                        )
                        log(
                            {
                                "event": "violation",
                                "sink": "builtins.open",
                                "validator": vid,
                                "msg": msg,
                                "mode": mode_eff.value,
                                "basename": p.name,
                                "full_path": str(p),
                                "taint_flow": _get_flow(),
                            }
                        )
                        if mode_eff == ViolationMode.BLOCK:
                            raise PolicyViolation(message)
                        # (warn/sanitize branches could be extended here if desired)
        return _ORIG["open"](file, mode, *args, **kwargs)

    builtins.open = guarded_open

    # subprocess.run
    @wraps(_ORIG["subprocess.run"])
    def guarded_run(*args, **kwargs):
        # Validate all strings (command and args).
        strings = _strings_from_args(*args, **kwargs)
        _enforce(policy, "subprocess.run", strings)
        return _ORIG["subprocess.run"](*args, **kwargs)

    subprocess.run = guarded_run

    # os.system
    @wraps(_ORIG["os.system"])
    def guarded_system(cmd):
        _enforce(policy, "os.system", [cmd])
        return _ORIG["os.system"](cmd)

    os.system = guarded_system

    # YAML: safe_load and load
    @wraps(_ORIG["yaml.safe_load"])
    def guarded_safe_load(stream, *args, **kwargs):
        kwargs.setdefault("Loader", yaml.SafeLoader)
        return _ORIG["yaml.load"](stream, **kwargs)

    yaml.safe_load = guarded_safe_load

    # yaml.load is forbidden for security reasons; use yaml.safe_load instead
    @wraps(_ORIG["yaml.load"])
    def forbidden_yaml_load(*args, **kwargs):
        _record_flowpoint("yaml.load")
        log(
            {
                "event": "blocked",
                "sink": "yaml.load",
                "reason": "yaml.load is forbidden for security reasons; use yaml.safe_load instead",
                "taint_flow": _get_flow(),
            }
        )
        raise PolicyViolation(
            "yaml.load is forbidden for security reasons; use yaml.safe_load instead"
        )

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
        # Patch Environment.from_string to capture source string
        # This is called by jinja2.Template() constructor
        if "jinja2.Environment.from_string" not in _ORIG:
            _ORIG["jinja2.Environment.from_string"] = jinja2.Environment.from_string

        # Only patch from_string if not already patched
        if jinja2.Environment.from_string is _ORIG["jinja2.Environment.from_string"]:

            @wraps(_ORIG["jinja2.Environment.from_string"])
            def guarded_from_string(self, source, *args, **kwargs):
                # Store the source string for later validation
                template = _ORIG["jinja2.Environment.from_string"](
                    self, source, *args, **kwargs
                )
                # Store source as an attribute for render() to access
                template._sentinel_source = source
                return template

            jinja2.Environment.from_string = guarded_from_string

        # Only save original if not already saved
        if "jinja2.Template.render" not in _ORIG:
            _ORIG["jinja2.Template.render"] = jinja2.Template.render

        # Only patch render if not already patched (current value matches original)
        if jinja2.Template.render is _ORIG["jinja2.Template.render"]:

            @wraps(_ORIG["jinja2.Template.render"])
            def guarded_jinja_render(self, *args, **kwargs):
                # Check template content and variables for injection patterns
                # Get template source from stored attribute
                template_content = getattr(self, "_sentinel_source", "")
                if not template_content:
                    # Fallback if source wasn't captured (e.g., template created before patching)
                    template_content = str(self)
                strings_to_check = [template_content]

                # Check template variables
                for arg in args:
                    if isinstance(arg, dict):
                        strings_to_check.extend(
                            str(v)
                            for v in arg.values()
                            if isinstance(v, (str, int, float))
                        )
                for v in kwargs.values():
                    if isinstance(v, (str, int, float)):
                        strings_to_check.append(str(v))

                _enforce(policy, "jinja2.Template.render", strings_to_check)
                return _ORIG["jinja2.Template.render"](self, *args, **kwargs)

            jinja2.Template.render = guarded_jinja_render

    # String template protection
    # Only save original if not already saved
    if "string.Template.substitute" not in _ORIG:
        _ORIG["string.Template.substitute"] = string.Template.substitute

    # Only patch if not already patched (current value matches original)
    if string.Template.substitute is _ORIG["string.Template.substitute"]:

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
        # Only save original if not already saved
        if "requests.get" not in _ORIG:
            _ORIG["requests.get"] = requests.get
        if "requests.post" not in _ORIG:
            _ORIG["requests.post"] = requests.post

        # Only patch if not already patched (current value matches original)
        if requests.get is _ORIG["requests.get"]:

            @wraps(_ORIG["requests.get"])
            def guarded_requests_get(url, **kwargs):
                _enforce(policy, "requests.get", [str(url)])
                return _ORIG["requests.get"](url, **kwargs)

            requests.get = guarded_requests_get

        if requests.post is _ORIG["requests.post"]:

            @wraps(_ORIG["requests.post"])
            def guarded_requests_post(url, **kwargs):
                _enforce(policy, "requests.post", [str(url)])
                return _ORIG["requests.post"](url, **kwargs)

            requests.post = guarded_requests_post

    if HAS_URLLIB:
        # Only save original if not already saved
        if "urllib.request.urlopen" not in _ORIG:
            _ORIG["urllib.request.urlopen"] = urllib.request.urlopen

        # Only patch if not already patched (current value matches original)
        if urllib.request.urlopen is _ORIG["urllib.request.urlopen"]:

            @wraps(_ORIG["urllib.request.urlopen"])
            def guarded_urlopen(url, **kwargs):
                url_str = str(url) if hasattr(url, "get_full_url") else str(url)
                _enforce(policy, "urllib.request.urlopen", [url_str])
                return _ORIG["urllib.request.urlopen"](url, **kwargs)

            urllib.request.urlopen = guarded_urlopen
