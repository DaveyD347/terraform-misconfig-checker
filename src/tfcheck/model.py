"""The resource model that rules run against.

Both input formats (Terraform source and ``terraform show -json`` plans) are
normalised into :class:`Module` objects holding :class:`Resource` objects whose
``config`` mirrors Terraform's own JSON shape: attributes are plain values and
nested blocks are lists of dicts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .evaluator import UNKNOWN, EncodedJSON, Ref, is_unknown

_IGNORE_RE = re.compile(
    r"tfcheck:ignore(?:[=:]\s*([A-Za-z0-9_\-]+(?:\s*,\s*[A-Za-z0-9_\-]+)*))?(.*)",
    re.IGNORECASE,
)


@dataclass
class Suppression:
    line: int
    rule_ids: frozenset[str] | None  # None = every rule
    reason: str
    whole_resource: bool = False
    target_line: int | None = None  # the line a non-resource-wide suppression applies to

    def matches(self, rule_id: str) -> bool:
        return self.rule_ids is None or rule_id.upper() in self.rule_ids


def parse_suppression(text: str, line: int) -> Suppression | None:
    m = _IGNORE_RE.search(text)
    if not m:
        return None
    ids = None
    if m.group(1):
        ids = frozenset(part.strip().upper() for part in m.group(1).split(","))
    reason = m.group(2).strip().lstrip("-—:").strip()
    if reason.endswith("*/"):
        reason = reason[:-2].strip()
    return Suppression(line, ids, reason)


@dataclass
class Resource:
    type: str
    name: str
    config: dict
    mode: str = "managed"  # or "data"
    module_path: str = ""  # "module.network." prefix for plan resources in child modules
    index: object = None
    file: str | None = None
    line: int | None = None
    end_line: int | None = None
    attr_lines: dict[str, int] = field(default_factory=dict)
    suppressions: list[Suppression] = field(default_factory=list)

    @property
    def base_address(self) -> str:
        prefix = "data." if self.mode == "data" else ""
        return f"{self.module_path}{prefix}{self.type}.{self.name}"

    @property
    def address(self) -> str:
        if self.index is None:
            return self.base_address
        if isinstance(self.index, str):
            return f'{self.base_address}["{self.index}"]'
        return f"{self.base_address}[{self.index}]"

    def get(self, key: str, default=None):
        """Attribute lookup that maps unknown and missing values to ``default``."""
        value = self.config.get(key, default)
        return default if value is None else value

    def blocks(self, key: str) -> list[dict]:
        value = self.config.get(key)
        if isinstance(value, dict):
            return [value]
        if isinstance(value, list):
            return [v for v in value if isinstance(v, dict)]
        return []

    def block(self, key: str) -> dict | None:
        found = self.blocks(key)
        return found[0] if found else None

    def line_for(self, path: str | None) -> int | None:
        if path is None:
            return self.line
        probe = path
        while probe:
            if probe in self.attr_lines:
                return self.attr_lines[probe]
            cut = max(probe.rfind("."), probe.rfind("["))
            probe = probe[:cut] if cut > 0 else ""
        return self.line


@dataclass
class Module:
    """One Terraform module directory (or one plan)."""

    path: str
    resources: list[Resource] = field(default_factory=list)
    source_kind: str = "hcl"  # "hcl" or "plan"

    def of_type(self, *types: str, mode: str = "managed") -> list[Resource]:
        return [r for r in self.resources if r.type in types and r.mode == mode]

    def resolve(self, value) -> Resource | None:
        """Follow a :class:`Ref` to the resource it points at."""
        if not isinstance(value, Ref):
            return None
        best = None
        for r in self.resources:
            if value.refers_to(r.base_address) and (best is None or len(r.base_address) > len(best.base_address)):
                best = r
        return best

    def links_to(self, value, target: Resource, *identity_attrs: str) -> bool:
        """Whether ``value`` (e.g. a ``bucket`` argument) identifies ``target``."""
        if isinstance(value, Ref):
            return value.refers_to(target.base_address)
        if isinstance(value, str) and not is_unknown(value):
            for attr in identity_attrs or ("id", "name", "arn"):
                if target.config.get(attr) == value:
                    return True
        return False

    def linked(self, rtype: str, target: Resource, attr: str, *identity_attrs: str) -> list[Resource]:
        return [r for r in self.of_type(rtype) if self.links_to(r.config.get(attr), target, *identity_attrs)]


def as_list(value) -> list:
    """Normalise "string or list of strings" values used across providers."""
    if value is None or value is UNKNOWN:
        return []
    if isinstance(value, list):
        return value
    return [value]


def known_str(value) -> str | None:
    return value if isinstance(value, str) else None


__all__ = [
    "Module",
    "Resource",
    "Suppression",
    "parse_suppression",
    "as_list",
    "known_str",
    "EncodedJSON",
]
