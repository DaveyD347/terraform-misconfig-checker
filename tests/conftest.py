import textwrap
from pathlib import Path

import pytest

from tfcheck.engine import Config, scan

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples"


@pytest.fixture
def scan_tf(tmp_path):
    """Scan Terraform source given as a string (or several files) and return the ScanResult."""

    def _scan(source: str | None = None, files: dict[str, str] | None = None, config: Config | None = None, **kw):
        files = dict(files or {})
        if source is not None:
            files["main.tf"] = source
        for name, text in files.items():
            path = tmp_path / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(textwrap.dedent(text))
        return scan([str(tmp_path)], config or Config(), **kw)

    return _scan


def ids(result, include_suppressed: bool = False) -> list[str]:
    findings = result.findings if include_suppressed else result.active
    return sorted(f.rule.id for f in findings)
