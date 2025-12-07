from typing import Any


class TaintedStr(str):
    """A string that carries taint tags."""

    __slots__ = ("_taint_tags",)

    def __new__(cls, value: str, tags: tuple[str, ...] = ()):
        obj = super().__new__(cls, value)
        obj._taint_tags = set(tags)
        return obj

    @property
    def taint_tags(self):
        return set(self._taint_tags)

    # Propagate taint on ops
    def _coerce(self, other):
        if isinstance(other, TaintedStr):
            return TaintedStr(str(other), tags=self.taint_tags | other.taint_tags)
        return TaintedStr(str(other), tags=self.taint_tags)

    def __add__(self, other):
        o = self._coerce(other)
        return TaintedStr(
            str.__add__(self, str(o)), tags=self.taint_tags | o.taint_tags
        )

    def format(self, *args, **kwargs):
        tags = set(self.taint_tags)
        for a in args:
            if isinstance(a, TaintedStr):
                tags |= a.taint_tags
        for v in kwargs.values():
            if isinstance(v, TaintedStr):
                tags |= v.taint_tags
        return TaintedStr(str.format(self, *args, **kwargs), tags=tags)


def taint(value: Any, *tags: str) -> Any:
    """Attach taint tags to strings recursively."""
    if isinstance(value, str) and not isinstance(value, TaintedStr):
        return TaintedStr(value, tags)
    if isinstance(value, TaintedStr):
        return TaintedStr(value, set(value.taint_tags) | set(tags))
    return value


def is_tainted(value: Any) -> bool:
    return isinstance(value, TaintedStr)


def taint_recursive(obj: Any, *tags: str) -> Any:
    """Recursively taint strings inside lists/dicts/tuples."""
    if isinstance(obj, dict):
        return {k: taint_recursive(v, *tags) for k, v in obj.items()}
    if isinstance(obj, list):
        return [taint_recursive(v, *tags) for v in obj]
    if isinstance(obj, tuple):
        return tuple(taint_recursive(v, *tags) for v in obj)
    if isinstance(obj, str):
        return taint(obj, *tags)
    return obj
