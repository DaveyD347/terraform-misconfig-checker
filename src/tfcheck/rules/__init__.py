"""Rule registry.

Each rule is a generator function decorated with :func:`rule`. It receives one
resource and its module, and yields :class:`Issue` objects. The engine takes
care of locations, suppressions and filtering.
"""

from __future__ import annotations

import enum
import re
import textwrap
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from ..model import Module, Resource


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            raise ValueError(f"unknown severity {value!r} (use low, medium, high or critical)") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass
class Issue:
    message: str
    path: str | None = None  # attribute path inside the resource, e.g. "ingress[0].cidr_blocks"
    severity: Severity | None = None  # overrides the rule default for this occurrence


Check = Callable[[Resource, Module], Iterable[Issue]]


@dataclass
class Rule:
    id: str
    title: str
    severity: Severity
    provider: str
    resource_types: tuple[str, ...]
    description: str
    fix_text: str  # prose part of the remediation ("" if there is none)
    fix_code: str  # Terraform snippet part of the remediation ("" if there is none)
    check: Check = field(repr=False)
    tags: tuple[str, ...] = ()

    @property
    def remediation(self) -> str:
        if self.fix_text and self.fix_code:
            return f"{self.fix_text}\n\n{self.fix_code}"
        return self.fix_text or self.fix_code

    def applies_to(self, res: Resource) -> bool:
        key = f"data.{res.type}" if res.mode == "data" else res.type
        return key in self.resource_types


REGISTRY: dict[str, Rule] = {}

_CODE_START = re.compile(r"^(resource |data |[a-z_]+\s*(=|\{))")


def split_remediation(text: str) -> tuple[str, str]:
    """Split a remediation docstring into (prose, Terraform snippet).

    Rules write remediations as prose, an indented snippet after a blank line,
    or a bare snippet. Docstring continuation lines carry source indentation,
    which is removed here.
    """
    text = text.strip("\n")
    if "\n\n" in text:
        prose, code = text.split("\n\n", 1)
        return " ".join(prose.split()), textwrap.dedent(code).strip("\n")
    if _CODE_START.match(text):
        first, _, rest = text.partition("\n")
        return "", (first + ("\n" + textwrap.dedent(rest) if rest else "")).strip("\n")
    return " ".join(text.split()), ""


def rule(
    id: str,
    title: str,
    severity: Severity,
    types: Iterable[str],
    description: str,
    remediation: str,
    tags: Iterable[str] = (),
):
    fix_text, fix_code = split_remediation(remediation)

    def decorator(func: Check) -> Check:
        if id in REGISTRY:
            raise ValueError(f"duplicate rule id {id}")
        provider = id.split("-", 1)[0].lower()
        REGISTRY[id] = Rule(
            id=id,
            title=title,
            severity=severity,
            provider={"aws": "aws", "az": "azure", "gcp": "gcp"}[provider],
            resource_types=tuple(types),
            description=" ".join(description.split()),
            fix_text=fix_text,
            fix_code=fix_code,
            check=func,
            tags=tuple(tags),
        )
        return func

    return decorator


def all_rules() -> list[Rule]:
    from . import aws, azure, gcp  # noqa: F401  (registers rules)

    return sorted(REGISTRY.values(), key=lambda r: r.id)


def get_rule(rule_id: str) -> Rule | None:
    all_rules()
    return REGISTRY.get(rule_id.upper())
