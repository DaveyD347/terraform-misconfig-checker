"""Output formats: text, JSON, SARIF 2.1.0 and Markdown."""

from __future__ import annotations

import json
from collections import defaultdict

from . import __version__
from .engine import Finding, ScanResult
from .rules import Rule, Severity

REPO_URL = "https://github.com/DaveyD347/terraform-misconfig-checker"

_COLORS = {
    Severity.CRITICAL: "\033[1;35m",
    Severity.HIGH: "\033[1;31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_DIM, _BOLD, _RESET = "\033[2m", "\033[1m", "\033[0m"


def _location(f: Finding) -> str:
    if f.file and f.line:
        return f"{f.file}:{f.line}"
    return f.file or "?"


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------


def render_text(result: ScanResult, color: bool = False, show_suppressed: bool = False) -> str:
    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines: list[str] = []
    shown = result.findings if show_suppressed else result.active
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in shown:
        by_file[f.file or "?"].append(f)
    for file in sorted(by_file):
        lines.append(c(_BOLD, file))
        for f in sorted(by_file[file], key=lambda x: (x.line or 0, -int(x.severity))):
            sev = f"{str(f.severity).upper():<8}"
            where = f"{f.line}" if f.line else "-"
            tag = c(_DIM, " (suppressed)") if f.suppressed else ""
            lines.append(f"  {where:>5}  {c(_COLORS[f.severity], sev)} {f.rule.id:<17} {f.resource.address}{tag}")
            lines.append(f"         {f.rule.title}: {f.message}")
        lines.append("")
    for err in result.errors:
        where = f"{err.file}:{err.line}" if err.line else err.file
        lines.append(c(_COLORS[Severity.HIGH], f"error: {where}: {err.message}"))
    if result.errors:
        lines.append("")
    counts = result.counts()
    total = len(result.active)
    parts = [f"{n} {sev}" for sev, n in counts.items() if n]
    summary = f"{total} finding{'s' if total != 1 else ''}"
    if parts:
        summary += f" ({', '.join(parts)})"
    summary += (
        f" in {result.resource_count} resource{'s' if result.resource_count != 1 else ''}"
        f" across {len(result.modules)} module{'s' if len(result.modules) != 1 else ''}"
    )
    if result.suppressed:
        summary += f", {len(result.suppressed)} suppressed"
    lines.append(c(_BOLD, summary))
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


def finding_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule.id,
        "title": f.rule.title,
        "severity": str(f.severity),
        "provider": f.rule.provider,
        "resource": f.resource.address,
        "resource_type": f.resource.type,
        "file": f.file,
        "line": f.line,
        "message": f.message,
        "remediation": f.rule.remediation,
        "suppressed": f.suppressed,
        "suppression_reason": f.suppression_reason or None,
    }


def render_json(result: ScanResult) -> str:
    doc = {
        "tool": "tfcheck",
        "version": __version__,
        "summary": {
            "modules": len(result.modules),
            "resources": result.resource_count,
            "rules": len(result.rules),
            "findings": len(result.active),
            "suppressed": len(result.suppressed),
            "by_severity": result.counts(),
        },
        "findings": [finding_dict(f) for f in result.findings],
        "errors": [{"file": e.file, "line": e.line, "message": e.message} for e in result.errors],
    }
    return json.dumps(doc, indent=2) + "\n"


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

_SARIF_LEVEL = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning", Severity.LOW: "note"}
_SECURITY_SEVERITY = {Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5", Severity.LOW: "3.0"}


def _sarif_rule(rule: Rule) -> dict:
    return {
        "id": rule.id,
        "name": "".join(w.capitalize() for w in rule.title.replace("-", " ").split() if w.isalnum()),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": f"{rule.description}\n\nRemediation:\n{rule.remediation}",
            "markdown": f"{rule.description}\n\n**Remediation**\n\n{_md_fix(rule)}",
        },
        "helpUri": f"{REPO_URL}/blob/main/docs/rules.md#{rule.id.lower()}",
        "defaultConfiguration": {"level": _SARIF_LEVEL[rule.severity]},
        "properties": {
            "security-severity": _SECURITY_SEVERITY[rule.severity],
            "tags": ["security", "terraform", rule.provider, *rule.tags],
            "precision": "high",
        },
    }


def render_sarif(result: ScanResult) -> str:
    rules = result.rules
    index = {r.id: i for i, r in enumerate(rules)}
    results = []
    for f in result.findings:
        location: dict = {"physicalLocation": {"artifactLocation": {"uri": f.file or "unknown"}}}
        if f.line:
            location["physicalLocation"]["region"] = {"startLine": f.line}
        location["logicalLocations"] = [{"fullyQualifiedName": f.resource.address, "kind": "resource"}]
        entry = {
            "ruleId": f.rule.id,
            "ruleIndex": index[f.rule.id],
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.resource.address}: {f.message}"},
            "locations": [location],
            "partialFingerprints": {"tfcheck/v1": f"{f.rule.id}:{f.resource.address}:{f.message}"},
            "properties": {"severity": str(f.severity), "security-severity": _SECURITY_SEVERITY[f.severity]},
        }
        if f.suppressed:
            entry["suppressions"] = [{"kind": "inSource", "justification": f.suppression_reason or ""}]
        results.append(entry)
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tfcheck",
                        "version": __version__,
                        "informationUri": REPO_URL,
                        "rules": [_sarif_rule(r) for r in rules],
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": not result.errors,
                        "toolExecutionNotifications": [
                            {
                                "level": "error",
                                "message": {"text": e.message},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": e.file},
                                            **({"region": {"startLine": e.line}} if e.line else {}),
                                        }
                                    }
                                ],
                            }
                            for e in result.errors
                        ],
                    }
                ],
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"


# ---------------------------------------------------------------------------
# Markdown (PR comments, GitHub job summaries)
# ---------------------------------------------------------------------------

_EMOJI = {Severity.CRITICAL: "🟣", Severity.HIGH: "🔴", Severity.MEDIUM: "🟠", Severity.LOW: "🔵"}


def _md_fix(rule: Rule) -> str:
    parts = []
    if rule.fix_text:
        parts.append(rule.fix_text)
    if rule.fix_code:
        parts.append(f"```hcl\n{rule.fix_code}\n```")
    return "\n\n".join(parts)


def _md_escape(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    out = ["## Terraform misconfiguration report", ""]
    counts = result.counts()
    out.append("| Severity | Findings |")
    out.append("|---|---:|")
    for sev in sorted(Severity, reverse=True):
        out.append(f"| {_EMOJI[sev]} {str(sev).capitalize()} | {counts[str(sev)]} |")
    out.append("")
    out.append(
        f"Scanned **{result.resource_count}** resources in **{len(result.modules)}** module(s) "
        f"with **{len(result.rules)}** rules. "
        f"{len(result.active)} finding(s), {len(result.suppressed)} suppressed."
    )
    out.append("")
    if result.active:
        out.append("| Severity | Rule | Resource | Location | Issue |")
        out.append("|---|---|---|---|---|")
        for f in result.active:
            out.append(
                f"| {_EMOJI[f.severity]} {str(f.severity)} | `{f.rule.id}` | `{f.resource.address}` | "
                f"`{_location(f)}` | {_md_escape(f.rule.title)}: {_md_escape(f.message)} |"
            )
        out.append("")
        out.append("<details><summary>How to fix</summary>")
        out.append("")
        for rule in sorted({f.rule.id: f.rule for f in result.active}.values(), key=lambda r: r.id):
            out.append(f"#### {rule.id}: {rule.title}")
            out.append("")
            out.append(rule.description)
            out.append("")
            out.append(_md_fix(rule))
            out.append("")
        out.append("</details>")
        out.append("")
    else:
        out.append("No misconfigurations found. ✅")
        out.append("")
    if result.suppressed:
        out.append("<details><summary>Suppressed findings</summary>")
        out.append("")
        out.append("| Rule | Resource | Reason |")
        out.append("|---|---|---|")
        for f in result.suppressed:
            out.append(
                f"| `{f.rule.id}` | `{f.resource.address}` | {_md_escape(f.suppression_reason) or '_none given_'} |"
            )
        out.append("")
        out.append("</details>")
        out.append("")
    if result.errors:
        out.append("**Parse errors**")
        out.append("")
        for e in result.errors:
            out.append(f"- `{e.file}{':' + str(e.line) if e.line else ''}`: {_md_escape(e.message)}")
        out.append("")
    return "\n".join(out)


RENDERERS = {"json": render_json, "sarif": render_sarif, "markdown": render_markdown}
