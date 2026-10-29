import json
from pathlib import Path

from typer.testing import CliRunner

from pathlens.cli import app

SAMPLE = Path(__file__).parents[1] / "examples" / "sample.json"
runner = CliRunner()


def test_offline_cli_produces_three_outputs(tmp_path):
    out = tmp_path / "result"
    result = runner.invoke(
        app, ["scan", "example.com", "--snapshot", str(SAMPLE), "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    assert {p.name for p in out.iterdir()} == {"report.json", "report.md", "observations.json"}
    report = json.loads((out / "report.json").read_text())
    assert report["collection_mode"] == "snapshot"
    assert "candidates require manual review" in result.output
    assert "[HIGH] missing.example.com" in result.output
    assert "not proof" in (out / "report.md").read_text()


def test_cli_refuses_to_overwrite(tmp_path):
    out = tmp_path / "result"
    out.mkdir()
    original = out / "report.json"
    original.write_text("keep me")
    result = runner.invoke(
        app, ["scan", "example.com", "--snapshot", str(SAMPLE), "--output", str(out)]
    )
    assert result.exit_code == 1
    assert original.read_text() == "keep me"
    assert not (out / "report.md").exists()


def test_snapshot_domain_must_match_requested_domain(tmp_path):
    result = runner.invoke(
        app, ["scan", "other.example", "--snapshot", str(SAMPLE), "--output", str(tmp_path)]
    )
    assert result.exit_code == 1
    assert "does not match" in result.output


def test_cli_does_not_run_live_without_authorized(tmp_path):
    result = runner.invoke(app, ["scan", "example.com", "--output", str(tmp_path)])
    assert result.exit_code == 1
    assert "authorization" in result.output
