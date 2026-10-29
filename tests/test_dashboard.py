import json
import shutil
import subprocess
from importlib.resources import files
from pathlib import Path

import pytest
from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.cli import app
from pathlens.models import Snapshot


def test_dashboard_assets_are_installed_and_demo_matches_fixture():
    root = files("pathlens").joinpath("dashboard")
    for name in ("index.html", "styles.css", "app.js", "demo.js"):
        assert root.joinpath(name).is_file()
    script = root.joinpath("demo.js").read_text(encoding="utf-8")
    demo = json.loads(script.removeprefix("window.PATHLENS_DEMO = ").strip().removesuffix(";"))
    fixture = Path(__file__).parents[1] / "examples" / "sample.json"
    report = analyze(Snapshot.model_validate_json(fixture.read_text()))
    assert demo["domain"] == "example.com"
    assert [(a["name"], a["priority"]) for a in demo["assets"]] == [
        (a.name, a.priority) for a in report.assets
    ]
    assert demo["stix_correlation"]["match_count"] == 2


def test_dashboard_is_local_and_has_no_external_dependencies():
    root = files("pathlens").joinpath("dashboard")
    html = root.joinpath("index.html").read_text(encoding="utf-8")
    appjs = root.joinpath("app.js").read_text(encoding="utf-8")
    css = root.joinpath("styles.css").read_text(encoding="utf-8")
    assert "Content-Security-Policy" in html
    assert "https://" not in html + css
    assert "innerHTML" not in appjs
    assert "fetch(" not in appjs
    assert "XMLHttpRequest" not in appjs


def test_dashboard_cli_can_print_without_opening_browser(monkeypatch):
    monkeypatch.setattr("webbrowser.open", lambda *_: (_ for _ in ()).throw(AssertionError()))
    result = CliRunner().invoke(app, ["dashboard", "--no-open"])
    assert result.exit_code == 0, result.output
    assert "file:" in result.output
    assert "dashboard/index.html" in result.output


def test_dashboard_cli_opens_the_local_file(monkeypatch):
    opened = []
    monkeypatch.setattr("webbrowser.open", lambda url: opened.append(url) or True)
    result = CliRunner().invoke(app, ["dashboard"])
    assert result.exit_code == 0, result.output
    assert len(opened) == 1 and opened[0].startswith("file:")


def test_dashboard_cli_reports_browser_launch_failure(monkeypatch):
    monkeypatch.setattr("webbrowser.open", lambda _: False)
    result = CliRunner().invoke(app, ["dashboard"])
    assert result.exit_code != 0
    assert "Open the address above manually" in result.output


def test_dashboard_state_and_offline_file_handling():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js is unavailable for dashboard logic tests")
    test_file = Path(__file__).parent / "dashboard_dom.cjs"
    result = subprocess.run([node, str(test_file)], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    assert "passed" in result.stdout
