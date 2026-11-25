"""Run rules over loaded modules and produce findings."""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from .loader import LoadError, load
from .model import Module, Resource
from .rules import Rule, Severity, all_rules


@dataclass
class Finding:
    rule: Rule
    severity: Severity
    resource: Resource
    message: str
    file: str | None
    line: int | None
    suppressed: bool = False
    suppression_reason: str = ""

    @property
    def rule_id(self) -> str:
        return self.rule.id

    def sort_key(self):
        return (-int(self.severity), self.file or "", self.line or 0, self.rule.id)


@dataclass
class Config:
    skip_rules: set[str] = field(default_factory=set)
    only_rules: set[str] = field(default_factory=set)
    exclude_paths: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    min_severity: Severity = Severity.LOW
    fail_on: Severity | None = Severity.LOW

    @classmethod
    def from_file(cls, path: Path) -> Config:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
        data = data.get("tfcheck", data)
        known = {"skip_rules", "only_rules", "exclude_paths", "severity_overrides", "min_severity", "fail_on"}
        unknown = set(data) - known
        if unknown:
            raise ValueError(f"{path}: unknown setting(s): {', '.join(sorted(unknown))}")
        cfg = cls()
        cfg.skip_rules = {r.upper() for r in data.get("skip_rules", [])}
        cfg.only_rules = {r.upper() for r in data.get("only_rules", [])}
        cfg.exclude_paths = list(data.get("exclude_paths", []))
        cfg.severity_overrides = {k.upper(): Severity.parse(v) for k, v in data.get("severity_overrides", {}).items()}
        if "min_severity" in data:
            cfg.min_severity = Severity.parse(data["min_severity"])
        if "fail_on" in data:
            cfg.fail_on = None if data["fail_on"] == "none" else Severity.parse(data["fail_on"])
        return cfg


CONFIG_NAMES = (".tfcheck.toml", "tfcheck.toml")


def find_config(paths: list[str]) -> Path | None:
    candidates = [Path.cwd()] + [Path(p) if Path(p).is_dir() else Path(p).parent for p in paths]
    for base in candidates:
        for name in CONFIG_NAMES:
            if (base / name).is_file():
                return base / name
    return None


@dataclass
class ScanResult:
    findings: list[Finding]
    errors: list[LoadError]
    modules: list[Module]
    rules: list[Rule]

    @property
    def active(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    @property
    def resource_count(self) -> int:
        return sum(1 for m in self.modules for r in m.resources if r.mode == "managed")

    def counts(self) -> dict[str, int]:
        out = {str(s): 0 for s in sorted(Severity, reverse=True)}
        for f in self.active:
            out[str(f.severity)] += 1
        return out

    def failed(self, threshold: Severity | None) -> bool:
        return threshold is not None and any(f.severity >= threshold for f in self.active)


def select_rules(config: Config) -> list[Rule]:
    rules = all_rules()
    unknown = (config.skip_rules | config.only_rules | set(config.severity_overrides)) - {r.id for r in rules}
    if unknown:
        raise ValueError(f"unknown rule id(s): {', '.join(sorted(unknown))}")
    if config.only_rules:
        rules = [r for r in rules if r.id in config.only_rules]
    return [r for r in rules if r.id not in config.skip_rules]


def scan(
    paths: list[str],
    config: Config | None = None,
    var_files: list[str] | None = None,
    variables: dict | None = None,
) -> ScanResult:
    config = config or Config()
    rules = select_rules(config)
    loaded = load(paths, var_files=var_files, variables=variables, exclude=config.exclude_paths)
    findings: list[Finding] = []
    for module in loaded.modules:
        findings.extend(check_module(module, rules, config))
    findings.sort(key=Finding.sort_key)
    return ScanResult(findings, loaded.errors, loaded.modules, rules)


def check_module(module: Module, rules: list[Rule], config: Config | None = None) -> list[Finding]:
    config = config or Config()
    out = []
    for res in module.resources:
        for rule in rules:
            if not rule.applies_to(res):
                continue
            for issue in rule.check(res, module) or ():
                severity = config.severity_overrides.get(rule.id) or issue.severity or rule.severity
                if severity < config.min_severity:
                    continue
                line = res.line_for(issue.path)
                finding = Finding(rule, severity, res, issue.message, _display_path(res.file), line)
                _apply_suppressions(finding, res)
                out.append(finding)
    return out


def _apply_suppressions(finding: Finding, res: Resource) -> None:
    for sup in res.suppressions:
        if not sup.matches(finding.rule.id):
            continue
        if sup.whole_resource or (finding.line is not None and finding.line == sup.target_line):
            finding.suppressed = True
            finding.suppression_reason = sup.reason
            return


def _display_path(path: str | None) -> str | None:
    if path is None:
        return None
    try:
        rel = os.path.relpath(path)
    except ValueError:  # different drive on Windows
        return Path(path).as_posix()
    return Path(path).as_posix() if rel.startswith("..") else Path(rel).as_posix()
