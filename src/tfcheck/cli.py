"""Command line interface."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .engine import Config, find_config, scan
from .report import RENDERERS, render_text
from .rules import Severity, all_rules, get_rule

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2
_SUBCOMMANDS = {"scan", "rules", "explain"}


def _severity(value: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _fail_on(value: str):
    return None if value == "none" else _severity(value)


def _var(value: str) -> tuple[str, object]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("expected NAME=VALUE")
    name, raw = value.split("=", 1)
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = raw
    return name, parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tfcheck",
        description="Find security misconfigurations in Terraform code and plans.",
    )
    parser.add_argument("--version", action="version", version=f"tfcheck {__version__}")
    sub = parser.add_subparsers(dest="command")

    s = sub.add_parser("scan", help="scan Terraform directories, .tf files or plan JSON (default command)")
    s.add_argument("paths", nargs="*", default=["."], help="directories, .tf files or `terraform show -json` output")
    s.add_argument("-f", "--format", choices=["text", "json", "sarif", "markdown"], default="text")
    s.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    s.add_argument(
        "--fail-on",
        choices=["none", "low", "medium", "high", "critical"],
        type=str.lower,
        help="exit 1 if findings at or above this severity remain (default: low; 'none' never fails)",
    )
    s.add_argument("--min-severity", type=_severity, metavar="SEVERITY", help="hide findings below this severity")
    s.add_argument(
        "--skip", action="append", default=[], metavar="RULE", help="skip a rule (repeatable, or comma separated)"
    )
    s.add_argument("--only", action="append", default=[], metavar="RULE", help="run only these rules")
    s.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip matching paths")
    s.add_argument("--var-file", action="append", default=[], help="a .tfvars or .tfvars.json file")
    s.add_argument("--var", action="append", default=[], type=_var, metavar="NAME=VALUE", help="set a variable")
    s.add_argument("--config", help="path to a tfcheck.toml config file")
    s.add_argument("--no-config", action="store_true", help="ignore .tfcheck.toml files")
    s.add_argument("--show-suppressed", action="store_true", help="list suppressed findings in text output")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    s.add_argument("--sarif-file", metavar="PATH", help="also write SARIF to PATH, whatever --format is")
    s.add_argument(
        "--github",
        action="store_true",
        help="emit GitHub Actions annotations, a job summary and step outputs (used by the Action)",
    )

    r = sub.add_parser("rules", help="list available rules")
    r.add_argument("-f", "--format", choices=["text", "json", "markdown"], default="text")
    r.add_argument("--provider", choices=["aws", "azure", "gcp"])

    e = sub.add_parser("explain", help="show details and the fix for one rule")
    e.add_argument("rule_id")
    return parser


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or (argv[0] not in _SUBCOMMANDS and argv[0] not in ("-h", "--help", "--version")):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    try:
        if args.command == "rules":
            return _cmd_rules(args)
        if args.command == "explain":
            return _cmd_explain(args)
        return _cmd_scan(args)
    except (ValueError, FileNotFoundError, OSError) as exc:
        print(f"tfcheck: error: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _split(values: list[str]) -> set[str]:
    return {part.strip().upper() for v in values for part in v.split(",") if part.strip()}


def _cmd_scan(args) -> int:
    config = Config()
    if args.config:
        config = Config.from_file(Path(args.config))
    elif not args.no_config:
        found = find_config(args.paths)
        if found:
            config = Config.from_file(found)
    config.skip_rules |= _split(args.skip)
    if args.only:
        config.only_rules = _split(args.only)
    config.exclude_paths += args.exclude
    if args.min_severity is not None:
        config.min_severity = args.min_severity
    fail_on = config.fail_on if args.fail_on is None else _fail_on(args.fail_on)

    result = scan(args.paths, config, var_files=args.var_file, variables=dict(args.var))

    if args.format == "text":
        color = not args.no_color and not args.output and sys.stdout.isatty() and "NO_COLOR" not in os.environ
        report = render_text(result, color=color, show_suppressed=args.show_suppressed)
    else:
        report = RENDERERS[args.format](result)
    if args.output:
        Path(args.output).write_text(report, encoding="utf-8")
    else:
        sys.stdout.write(report)

    if args.sarif_file:
        Path(args.sarif_file).write_text(RENDERERS["sarif"](result), encoding="utf-8")
    if args.github:
        _github(result)

    if result.failed(fail_on):
        return EXIT_FINDINGS
    if result.errors:
        return EXIT_ERROR
    return EXIT_OK


def _cmd_rules(args) -> int:
    rules = [r for r in all_rules() if args.provider in (None, r.provider)]
    if args.format == "json":
        data = [
            {
                "id": r.id,
                "title": r.title,
                "severity": str(r.severity),
                "provider": r.provider,
                "resource_types": list(r.resource_types),
                "description": r.description,
                "remediation": r.remediation,
                "tags": list(r.tags),
            }
            for r in rules
        ]
        print(json.dumps(data, indent=2))
    elif args.format == "markdown":
        print("| ID | Severity | Title | Resources |")
        print("|---|---|---|---|")
        for r in rules:
            types = ", ".join(f"`{t}`" for t in r.resource_types)
            print(f"| [{r.id}](docs/rules.md#{r.id.lower()}) | {r.severity} | {r.title} | {types} |")
    else:
        for r in rules:
            print(f"{r.id:<18} {str(r.severity):<9} {r.title}")
        print(f"\n{len(rules)} rules")
    return EXIT_OK


def _cmd_explain(args) -> int:
    rule = get_rule(args.rule_id)
    if rule is None:
        print(f"tfcheck: unknown rule {args.rule_id!r}; run `tfcheck rules` to list them", file=sys.stderr)
        return EXIT_ERROR
    print(f"{rule.id}: {rule.title}")
    print(f"Severity: {rule.severity}    Provider: {rule.provider}")
    print(f"Resources: {', '.join(rule.resource_types)}")
    print()
    print(rule.description)
    print()
    print("Fix:")
    for line in rule.remediation.splitlines():
        print(f"  {line}")
    print()
    print(f"Suppress with a comment on or above the resource:  # tfcheck:ignore={rule.id} <reason>")
    return EXIT_OK


def _github(result) -> None:
    """Workflow commands, job summary and step outputs for GitHub Actions."""
    from .report import render_markdown
    from .rules import Severity as Sev

    level = {Sev.CRITICAL: "error", Sev.HIGH: "error", Sev.MEDIUM: "warning", Sev.LOW: "notice"}

    def esc(text: str) -> str:
        return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def esc_prop(text: str) -> str:
        return esc(text).replace(":", "%3A").replace(",", "%2C")

    for f in result.active:
        props = [f"title={esc_prop(f'{f.rule.id} {f.rule.title}')}"]
        if f.file:
            props.insert(0, f"file={esc_prop(f.file)}")
            if f.line:
                props.insert(1, f"line={f.line}")
        print(f"::{level[f.severity]} {','.join(props)}::{esc(f'{f.resource.address}: {f.message}')}")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(render_markdown(result) + "\n")
    outputs = os.environ.get("GITHUB_OUTPUT")
    if outputs:
        with open(outputs, "a", encoding="utf-8") as fh:
            fh.write(f"findings={len(result.active)}\n")
            for sev, n in result.counts().items():
                fh.write(f"{sev}={n}\n")
