import json
from pathlib import Path

from typer.testing import CliRunner

from pathlens.analysis import analyze
from pathlens.cli import app
from pathlens.models import Report, Snapshot
from pathlens.output import markdown
from pathlens.stix_patterns import correlate_stix

EXAMPLES = Path(__file__).parents[1] / "examples"


def documents():
    snapshot = Snapshot.model_validate_json((EXAMPLES / "sample.json").read_text())
    bundle = json.loads((EXAMPLES / "stix-pattern-indicators.json").read_text())
    bundle["objects"][0]["pattern"] = "[domain-name:value = 'cdn.example.com']"
    bundle["objects"][1]["pattern"] = "[file:name = 'unavailable']"
    return snapshot, bundle


def test_report_tracks_matched_evidence_and_indeterminate_without_asset_claims():
    snapshot, bundle = documents()
    report = analyze(snapshot)
    correlate_stix(report, snapshot, bundle)
    result, uncertain = report.stix_correlation.results
    assert result.status == "matched"
    assert result.evidence[0].name == "cdn.example.com"
    assert result.evidence[0].dns_record_index == 2
    assert uncertain.status == "indeterminate"
    assert report.stix_correlation.indeterminate_count == 1
    assert all(not asset.indicator_matches for asset in report.assets)
    assert "does not establish an attack" in markdown(report)
    assert Report.model_validate_json(report.model_dump_json()).stix_correlation == (
        report.stix_correlation
    )


def test_cli_scan_includes_complex_stix_in_both_reports(tmp_path):
    _, bundle = documents()
    source = tmp_path / "indicators.json"
    source.write_text(json.dumps(bundle))
    output = tmp_path / "out"
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(EXAMPLES / "sample.json"),
        "--stix-bundle", str(source), "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text())
    assert report["stix_correlation"]["match_count"] == 1
    assert report["stix_correlation"]["indeterminate_count"] == 1
    assert "cdn.example.com" in (output / "report.md").read_text()
    assert "STIX: 1 matches, 1 indeterminate" in result.output


def test_invalid_stix_is_not_silently_ignored(tmp_path):
    source = tmp_path / "null.json"
    source.write_text("null")
    output = tmp_path / "out"
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(EXAMPLES / "sample.json"),
        "--stix-bundle", str(source), "--output", str(output),
    ])
    assert result.exit_code != 0
    assert "Expected a STIX bundle" in result.output
    assert not output.exists()


def test_selection_requires_bundle(tmp_path):
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(EXAMPLES / "sample.json"),
        "--stix-indicator-id", "indicator--missing", "--output", str(tmp_path / "out"),
    ])
    assert result.exit_code != 0
    assert "requires --stix-bundle" in result.output


def test_report_escapes_untrusted_markdown_and_uses_private_permissions(tmp_path):
    snapshot, _ = documents()
    report = analyze(snapshot)
    report.warnings.append("![leak](https://outside.example/image) <script>alert('x')</script>\x1b")
    text = markdown(report)
    assert "![leak](" not in text
    assert r"\!\[leak\](" in text
    assert "<script>" not in text
    assert "\x1b" not in text
    from pathlens.output import write_report

    for path in write_report(report, snapshot, tmp_path / "private"):
        assert path.stat().st_mode & 0o077 == 0


def test_supplied_stix_demo_produces_two_matches(tmp_path):
    output = tmp_path / "demo"
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(EXAMPLES / "sample.json"),
        "--stix-bundle", str(EXAMPLES / "stix-snapshot-indicators.json"),
        "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text())
    assert report["stix_correlation"]["match_count"] == 2
    second = report["stix_correlation"]["results"][1]
    assert {item["name"] for item in second["evidence"]} == {
        "cdn.example.com", "ip.example.com"
    }


def test_scan_selects_only_the_requested_indicator(tmp_path):
    output = tmp_path / "selected"
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(EXAMPLES / "sample.json"),
        "--stix-bundle", str(EXAMPLES / "stix-snapshot-indicators.json"),
        "--stix-indicator-id", "indicator--00000000-0000-4000-8000-000000000003",
        "--output", str(output),
    ])
    assert result.exit_code == 0, result.output
    report = json.loads((output / "report.json").read_text())
    assert len(report["stix_correlation"]["results"]) == 1


def test_scan_rejects_too_many_observations_without_partial_report(tmp_path):
    snapshot, _ = documents()
    snapshot.dns_records = [snapshot.dns_records[2].model_copy() for _ in range(26)]
    source = tmp_path / "snapshot.json"
    source.write_text(snapshot.model_dump_json())
    output = tmp_path / "out"
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(source),
        "--stix-bundle", str(EXAMPLES / "stix-snapshot-indicators.json"),
        "--output", str(output),
    ])
    assert result.exit_code != 0
    assert "observation limit exceeded" in result.output
    assert not output.exists()


def test_snapshot_warning_cannot_control_terminal(tmp_path):
    snapshot, _ = documents()
    snapshot.warnings = ["before\x1b[31mafter"]
    source = tmp_path / "snapshot.json"
    source.write_text(snapshot.model_dump_json())
    result = CliRunner().invoke(app, [
        "scan", "example.com", "--snapshot", str(source), "--output", str(tmp_path / "out"),
    ])
    assert result.exit_code == 0
    assert "\x1b" not in result.output
    assert "before [31mafter" in result.output
