"""Helpers shared by provider rule packs: network exposure and IAM policy parsing."""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from ..evaluator import UNKNOWN, EncodedJSON, Ref, is_unknown
from ..model import Module, Resource, as_list

# ---------------------------------------------------------------------------
# Network exposure
# ---------------------------------------------------------------------------

ADMIN_PORTS = {22: "SSH", 23: "Telnet", 3389: "RDP", 5985: "WinRM", 5986: "WinRM", 5900: "VNC"}
DATA_PORTS = {
    1433: "SQL Server",
    1521: "Oracle",
    2375: "Docker API",
    2376: "Docker API",
    3306: "MySQL",
    5432: "PostgreSQL",
    5984: "CouchDB",
    6379: "Redis",
    9042: "Cassandra",
    9200: "Elasticsearch",
    9300: "Elasticsearch",
    11211: "Memcached",
    27017: "MongoDB",
}
SENSITIVE_PORTS = {**ADMIN_PORTS, **DATA_PORTS}

_ANY_SOURCE_WORDS = {"*", "internet", "any", "0.0.0.0"}


def is_public_cidr(value) -> bool:
    """True for sources that mean "the whole internet"."""
    if not isinstance(value, str):
        return False
    v = value.strip().lower()
    if v in _ANY_SOURCE_WORDS:
        return True
    try:
        return ipaddress.ip_network(v, strict=False).prefixlen == 0
    except ValueError:
        return False


@dataclass
class Exposure:
    all_ports: bool
    services: list[str]  # e.g. ["22 (SSH)"]

    def describe(self) -> str:
        if self.all_ports:
            return "all ports"
        return ", ".join(self.services)


def exposure_for_range(low, high, protocol) -> Exposure | None:
    """Classify a port range opened to the internet. Returns None when nothing sensitive is exposed."""
    proto = str(protocol).lower() if isinstance(protocol, (str, int)) else None
    if proto in ("-1", "all", "*"):
        return Exposure(True, [])
    if proto in ("icmp", "icmpv6", "1", "58", "ah", "esp"):
        return None
    if not isinstance(low, int) or not isinstance(high, int):
        return None
    if low <= 0 and high >= 65535 or (low == -1 and high == -1):
        return Exposure(True, [])
    hits = [f"{p} ({name})" for p, name in sorted(SENSITIVE_PORTS.items()) if low <= p <= high]
    return Exposure(False, hits) if hits else None


def parse_port_spec(spec) -> tuple[int, int] | None:
    """Azure / GCP style port specs: "22", "1000-2000", "*", 22."""
    if isinstance(spec, bool):
        return None
    if isinstance(spec, int):
        return spec, spec
    if not isinstance(spec, str):
        return None
    s = spec.strip()
    if s in ("*", ""):
        return 0, 65535
    if "-" in s:
        a, _, b = s.partition("-")
        if a.strip().isdigit() and b.strip().isdigit():
            return int(a), int(b)
        return None
    return (int(s), int(s)) if s.isdigit() else None


def exposure_for_specs(specs, protocol) -> Exposure | None:
    found = Exposure(False, [])
    for spec in specs:
        rng = parse_port_spec(spec)
        if rng is None:
            continue
        exp = exposure_for_range(rng[0], rng[1], protocol)
        if exp is None:
            continue
        if exp.all_ports:
            return exp
        found.services.extend(s for s in exp.services if s not in found.services)
    return found if found.services else None


# ---------------------------------------------------------------------------
# IAM-style policy documents
# ---------------------------------------------------------------------------


@dataclass
class Statement:
    effect: str
    actions: list
    not_actions: list
    resources: list
    principals: list  # flattened principal identifiers, e.g. ["*", "arn:aws:iam::123:root"]
    has_condition: bool
    path: str | None  # location of the statement inside the resource


def decode_policy(value, module: Module | None = None):
    """Return ``(policy_dict, via_document)`` for the many ways a policy can be written."""
    if isinstance(value, EncodedJSON):
        value = value.data
    if isinstance(value, Ref) and module is not None:
        target = module.resolve(value)
        if target is not None and target.mode == "data" and target.type == "aws_iam_policy_document":
            return policy_from_document(target), target
        return None, None
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return None, None
    return (value, None) if isinstance(value, dict) else (None, None)


def policy_from_document(doc: Resource) -> dict:
    statements = []
    for st in doc.blocks("statement"):
        principals: dict = {}
        for p in _blocks(st.get("principals")):
            principals.setdefault(p.get("type", "AWS"), []).extend(as_list(p.get("identifiers")))
        out = {
            "Effect": st.get("effect") or "Allow",
            "Action": as_list(st.get("actions")),
            "NotAction": as_list(st.get("not_actions")),
            "Resource": as_list(st.get("resources")),
        }
        if principals:
            out["Principal"] = principals
        if _blocks(st.get("condition")):
            out["Condition"] = True
        statements.append(out)
    return {"Statement": statements}


def _blocks(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def iter_statements(policy: dict, base_path: str | None = None):
    raw = policy.get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    if not isinstance(raw, list):
        return
    for i, st in enumerate(raw):
        if not isinstance(st, dict):
            continue
        effect = st.get("Effect", "Allow")
        yield Statement(
            effect=effect if isinstance(effect, str) else "Allow",
            actions=[a for a in as_list(st.get("Action")) if isinstance(a, str)],
            not_actions=[a for a in as_list(st.get("NotAction")) if isinstance(a, str)],
            resources=[r for r in as_list(st.get("Resource")) if isinstance(r, str)],
            principals=_principal_ids(st.get("Principal")),
            has_condition=bool(st.get("Condition")),
            path=f"{base_path}[{i}]" if base_path == "statement" else base_path,
        )


def _principal_ids(principal) -> list[str]:
    if principal is None or principal is UNKNOWN:
        return []
    if isinstance(principal, str):
        return [principal]
    out = []
    if isinstance(principal, dict):
        for value in principal.values():
            out.extend(v for v in as_list(value) if isinstance(v, str))
    return out


def policy_statements(res: Resource, attr: str, module: Module):
    """Statements of a policy argument, skipping ones defined in a referenced policy document.

    Findings for documents are reported on the ``aws_iam_policy_document`` data
    source itself, which is where the fix belongs, so following the reference
    here would only duplicate them. Plans render the document to a JSON string,
    so the string is compared against rendered documents in the same module.
    """
    value = res.config.get(attr)
    if isinstance(value, Ref):
        return []
    if isinstance(value, str) and any(
        d.config.get("json") == value for d in module.of_type("aws_iam_policy_document", mode="data")
    ):
        return []
    policy, _ = decode_policy(value, module)
    if policy is None:
        return []
    return list(iter_statements(policy, attr))


def all_statements(res: Resource, attr: str, module: Module):
    """Like :func:`policy_statements` but follows references to policy documents."""
    policy, _ = decode_policy(res.config.get(attr), module)
    return list(iter_statements(policy, attr)) if policy else []


def is_true(value) -> bool:
    return value is True or value == "true"


def is_false(value) -> bool:
    return value is False or value == "false"


def known(value) -> bool:
    return value is not None and not is_unknown(value)
