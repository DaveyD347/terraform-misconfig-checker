"""Load ``terraform show -json`` output (plans and state) into modules.

Scanning a plan sees what Terraform will actually create: module inputs,
``count``/``for_each`` expansion and variables are all resolved. Values that
are only known after apply are marked unknown using ``after_unknown``, and
references recorded in the ``configuration`` section are kept as
:class:`Ref` objects so cross-resource rules still work.
"""

from __future__ import annotations

from .evaluator import UNKNOWN, Ref
from .model import Module, Resource


def is_plan_document(doc) -> bool:
    return isinstance(doc, dict) and "format_version" in doc and ("planned_values" in doc or "values" in doc)


def load_plan(doc: dict, filename: str) -> Module:
    root = (doc.get("planned_values") or doc.get("values") or {}).get("root_module", {})
    unknown_by_address = {}
    for change in doc.get("resource_changes", []):
        after_unknown = (change.get("change") or {}).get("after_unknown")
        if isinstance(after_unknown, dict):
            unknown_by_address[change.get("address")] = after_unknown

    references = {}
    _collect_references((doc.get("configuration") or {}).get("root_module", {}), "", references)

    module = Module(path=filename, source_kind="plan")
    for raw in _walk_resources(root):
        values = dict(raw.get("values") or {})
        _apply_unknown(values, unknown_by_address.get(raw.get("address"), {}))
        address = raw.get("address", "")
        module_path = _module_prefix(address)
        rtype, name, mode = raw.get("type", ""), raw.get("name", ""), raw.get("mode", "managed")
        base = f"{module_path}{'data.' if mode == 'data' else ''}{rtype}.{name}"
        _apply_references(values, references.get(base, {}), module_path)
        module.resources.append(
            Resource(
                type=rtype,
                name=name,
                config=values,
                mode=mode,
                module_path=module_path,
                index=raw.get("index"),
                file=filename,
            )
        )
    return module


def _walk_resources(mod: dict):
    yield from mod.get("resources", []) or []
    for child in mod.get("child_modules", []) or []:
        yield from _walk_resources(child)


def _module_prefix(address: str) -> str:
    """``module.net.module.sg.aws_security_group.x[0]`` -> ``module.net.module.sg.``"""
    parts = []
    rest = address
    while rest.startswith("module."):
        name_and_rest = rest[len("module.") :]
        end = 0
        depth = 0
        while end < len(name_and_rest):
            ch = name_and_rest[end]
            if ch == "[":
                depth += 1
            elif ch == "]":
                depth -= 1
            elif ch == "." and depth == 0:
                break
            end += 1
        segment = name_and_rest[:end]
        segment = segment.split("[", 1)[0]  # drop module instance keys
        parts.append(f"module.{segment}.")
        rest = name_and_rest[end + 1 :]
    return "".join(parts)


def _apply_unknown(values, unknown) -> None:
    if not isinstance(unknown, dict):
        return
    for key, flag in unknown.items():
        if flag is True:
            if values.get(key) is None:
                values[key] = UNKNOWN
        elif isinstance(flag, list) and isinstance(values.get(key), list):
            for item, item_flag in zip(values[key], flag, strict=False):
                if isinstance(item, dict):
                    _apply_unknown(item, item_flag)
        elif isinstance(flag, dict) and isinstance(values.get(key), dict):
            _apply_unknown(values[key], flag)


def _collect_references(cfg_module: dict, prefix: str, out: dict) -> None:
    for res in cfg_module.get("resources", []) or []:
        mode = res.get("mode", "managed")
        base = f"{prefix}{'data.' if mode == 'data' else ''}{res.get('type')}.{res.get('name')}"
        out[base] = res.get("expressions") or {}
    for name, call in (cfg_module.get("module_calls") or {}).items():
        _collect_references(call.get("module") or {}, f"{prefix}module.{name}.", out)


def _apply_references(values: dict, expressions: dict, prefix: str = "") -> None:
    for key, expr in expressions.items():
        if isinstance(expr, dict) and "references" in expr:
            refs = [r for r in expr["references"] if not r.startswith(("var.", "local.", "each.", "count."))]
            current = values.get(key)
            if refs and (current is None or current is UNKNOWN):
                values[key] = Ref(prefix + refs[0])
        elif isinstance(expr, list) and isinstance(values.get(key), list):
            for item_values, item_expr in zip(values[key], expr, strict=False):
                if isinstance(item_values, dict) and isinstance(item_expr, dict):
                    _apply_references(item_values, item_expr, prefix)
