"""Turn Terraform source directories and plan files into :class:`Module` objects."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import hcl
from .evaluator import UNKNOWN, Evaluator, contains_unknown
from .model import Module, Resource, Suppression, parse_suppression
from .plan import is_plan_document, load_plan

_SKIP_DIRS = {".terraform", ".git", "node_modules", ".terragrunt-cache", "__pycache__"}
_META_ARGS = {"depends_on", "lifecycle", "provider", "provisioner", "connection"}


@dataclass
class LoadError:
    file: str
    line: int | None
    message: str


@dataclass
class LoadResult:
    modules: list[Module] = field(default_factory=list)
    errors: list[LoadError] = field(default_factory=list)


def discover(paths: list[str], exclude: list[str] | None = None) -> tuple[list[tuple[str, list[Path]]], list[Path]]:
    """Group .tf files by directory; return (module dirs, plan files)."""
    exclude = exclude or []
    groups: dict[str, list[Path]] = {}
    plans: list[Path] = []

    def excluded(p: Path) -> bool:
        posix = p.as_posix()
        return any(Path(posix).match(pattern) or pattern.strip("/") in posix.split("/") for pattern in exclude)

    for raw in paths:
        p = Path(raw)
        if p.is_file():
            if p.suffix == ".json":
                plans.append(p)
            elif p.suffix == ".tf":
                groups.setdefault(str(p), []).append(p)
            continue
        if not p.is_dir():
            raise FileNotFoundError(raw)
        for root, dirs, files in os.walk(p):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS and not excluded(Path(root) / d))
            tf = sorted(Path(root) / f for f in files if f.endswith(".tf") and not excluded(Path(root) / f))
            if tf:
                groups[root] = tf
    return sorted(groups.items()), plans


def load(
    paths: list[str],
    var_files: list[str] | None = None,
    variables: dict | None = None,
    exclude: list[str] | None = None,
) -> LoadResult:
    result = LoadResult()
    groups, plans = discover(paths, exclude)
    extra_vars: dict = {}
    for vf in var_files or []:
        try:
            extra_vars.update(read_tfvars(Path(vf)))
        except (OSError, hcl.HCLError, ValueError) as exc:
            result.errors.append(LoadError(vf, getattr(exc, "line", None), _message(exc)))
    extra_vars.update(variables or {})

    for module_dir, files in groups:
        module, errors = load_module(module_dir, files, extra_vars)
        result.errors.extend(errors)
        if module.resources:
            result.modules.append(module)

    for plan_path in plans:
        try:
            doc = json.loads(plan_path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            result.errors.append(LoadError(str(plan_path), None, f"cannot read plan: {exc}"))
            continue
        if not is_plan_document(doc):
            result.errors.append(
                LoadError(str(plan_path), None, "not a Terraform plan (expected output of `terraform show -json`)")
            )
            continue
        result.modules.append(load_plan(doc, str(plan_path)))
    return result


def _message(exc: Exception) -> str:
    return exc.message if isinstance(exc, hcl.HCLError) else str(exc)


# ---------------------------------------------------------------------------
# tfvars
# ---------------------------------------------------------------------------


def read_tfvars(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
        if not isinstance(data, dict):
            raise ValueError(f"{path}: expected a JSON object")
        return data
    parsed = hcl.parse(text, str(path))
    ev = Evaluator()
    return {name: ev.eval(attr.expr) for name, attr in parsed.body.attributes.items()}


def _auto_var_files(module_dir: Path) -> list[Path]:
    files = []
    for name in ("terraform.tfvars", "terraform.tfvars.json"):
        if (module_dir / name).is_file():
            files.append(module_dir / name)
    files += sorted(module_dir.glob("*.auto.tfvars")) + sorted(module_dir.glob("*.auto.tfvars.json"))
    return files


# ---------------------------------------------------------------------------
# Modules
# ---------------------------------------------------------------------------


def load_module(module_dir: str, files: list[Path], extra_vars: dict | None = None) -> tuple[Module, list[LoadError]]:
    errors: list[LoadError] = []
    parsed: list[hcl.File] = []
    for f in files:
        try:
            parsed.append(hcl.parse(f.read_text(encoding="utf-8"), str(f)))
        except hcl.HCLError as exc:
            errors.append(LoadError(str(f), exc.line, exc.message))
        except (OSError, UnicodeDecodeError) as exc:
            errors.append(LoadError(str(f), None, str(exc)))

    declared: dict[str, object] = {}
    locals_: dict[str, hcl.Node] = {}
    const = Evaluator()
    for pf in parsed:
        for block in pf.body.blocks:
            if block.type == "variable" and block.labels:
                default = block.body.attributes.get("default")
                declared[block.labels[0]] = const.eval(default.expr) if default else UNKNOWN
            elif block.type == "locals":
                for name, attr in block.body.attributes.items():
                    locals_[name] = attr.expr

    values = dict(declared)
    dir_path = Path(module_dir) if Path(module_dir).is_dir() else Path(module_dir).parent
    for vf in _auto_var_files(dir_path):
        try:
            for k, v in read_tfvars(vf).items():
                if k in declared:
                    values[k] = v
        except (OSError, hcl.HCLError, ValueError) as exc:
            errors.append(LoadError(str(vf), getattr(exc, "line", None), _message(exc)))
    for k, v in (extra_vars or {}).items():
        if k in declared:
            values[k] = v

    ev = Evaluator(values, locals_)
    module = Module(path=str(module_dir))
    for pf in parsed:
        for block in pf.body.blocks:
            if block.type in ("resource", "data") and len(block.labels) == 2:
                module.resources.append(_build_resource(block, pf, ev))
    return module, errors


def _build_resource(block: hcl.Block, pf: hcl.File, ev: Evaluator) -> Resource:
    rtype, name = block.labels
    lines: dict[str, int] = {}
    config = _body_to_dict(block.body, ev, "", lines, top=True)
    res = Resource(
        type=rtype,
        name=name,
        config=config,
        mode="managed" if block.type == "resource" else "data",
        file=pf.filename,
        line=block.line,
        end_line=block.end_line,
        attr_lines=lines,
    )
    res.suppressions = _suppressions_for(block, pf.comments, set(lines.values()))
    return res


def _body_to_dict(body: hcl.Body, ev: Evaluator, prefix: str, lines: dict, top: bool = False) -> dict:
    out: dict = {}
    for name, attr in body.attributes.items():
        if top and name in _META_ARGS:
            continue
        out[name] = ev.eval(attr.expr)
        lines[prefix + name] = attr.line
    for block in body.blocks:
        if top and block.type in _META_ARGS:
            continue
        if block.type == "dynamic" and block.labels:
            _expand_dynamic(block, ev, prefix, out, lines)
            continue
        items = out.setdefault(block.type, [])
        if not isinstance(items, list):
            continue
        path = f"{prefix}{block.type}[{len(items)}]"
        lines[path] = block.line
        items.append(_body_to_dict(block.body, ev, path + ".", lines))
    return out


def _expand_dynamic(block: hcl.Block, ev: Evaluator, prefix: str, out: dict, lines: dict) -> None:
    target = block.labels[0]
    attrs = block.body.attributes
    iterator = target
    if "iterator" in attrs and isinstance(attrs["iterator"].expr, hcl.Variable):
        iterator = attrs["iterator"].expr.name
    content = next((b for b in block.body.blocks if b.type == "content"), None)
    if content is None:
        return
    coll = ev.eval(attrs["for_each"].expr) if "for_each" in attrs else UNKNOWN
    if isinstance(coll, dict):
        pairs = list(coll.items())
    elif isinstance(coll, list) and not contains_unknown(coll):
        pairs = [(v, v) if not isinstance(v, (dict, list)) else (i, v) for i, v in enumerate(coll)]
    else:
        pairs = [(UNKNOWN, UNKNOWN)]  # unknown collection: evaluate content once with unknown values
    items = out.setdefault(target, [])
    if not isinstance(items, list):
        return
    for key, value in pairs:
        scope = ev.with_scope({iterator: {"key": key, "value": value}})
        path = f"{prefix}{target}[{len(items)}]"
        lines[path] = content.line
        items.append(_body_to_dict(content.body, scope, path + ".", lines))


def _suppressions_for(block: hcl.Block, comments: dict[int, list[str]], code_lines: set[int]) -> list[Suppression]:
    """Comments directly above a block, or at the top of its body, cover the whole resource.

    Any other ``tfcheck:ignore`` comment inside the block covers a single line:
    its own line for a trailing comment, otherwise the line below it.
    """
    found: list[Suppression] = []
    header_lines = {block.line}
    ln = block.line - 1
    while ln in comments:
        header_lines.add(ln)
        ln -= 1
    ln = block.line + 1
    while ln in comments and ln not in code_lines and ln < block.end_line:
        header_lines.add(ln)
        ln += 1
    for ln in sorted(header_lines | set(range(block.line, block.end_line + 1))):
        for text in comments.get(ln, []):
            sup = parse_suppression(text, ln)
            if sup:
                sup.whole_resource = ln in header_lines
                # A trailing comment covers its own line; a comment on its own line covers the next one.
                sup.target_line = ln if ln in code_lines else ln + 1
                found.append(sup)
    return found
