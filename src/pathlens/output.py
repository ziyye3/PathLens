"""Deterministic JSON and readable Markdown output."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import Report, Snapshot


def _text(value: object) -> str:
    # Prevent user-supplied DNS text from breaking Markdown or injecting HTML.
    return html.escape(str(value), quote=True).replace("\n", " ").replace("\r", " ")


def markdown(report: Report) -> str:
    lines = [
        f"# PathLens: {_text(report.domain)}",
        "",
        f"- Collection mode: {_text(report.collection_mode)}",
        f"- Observed at: {_text(report.observed_at.isoformat())}",
        "- Scope: public observations; ownership and vulnerabilities are not confirmed.",
        f"- Threat feed: {_text(report.threat_feed.status)}; "
        f"{report.threat_feed.indicator_count} indicators; "
        f"{report.threat_feed.match_count} matches.",
        "",
        "## Assets",
    ]
    for asset in report.assets:
        lines += [
            "",
            f"### [{_text(asset.priority.upper())}] `{_text(asset.name)}`",
            "",
            f"- Sources: {_text(', '.join(asset.discovered_by))}",
        ]
        lines.append(f"- CNAME path: {_text(' → '.join(asset.cname_chain))}")
        lines.append(f"- Addresses: {_text(', '.join(asset.addresses) or 'none observed')}")
        for evidence in asset.discovery_evidence:
            reference = f" ({_text(evidence.reference)})" if evidence.reference else ""
            lines.append(
                f"- Discovery: {_text(evidence.source)}: {_text(evidence.description)}{reference}"
            )
        for warning in asset.warnings:
            lines.append(f"- Warning: {_text(warning)}")
        if not asset.findings:
            lines.append("- No matching rule. This is not a safety assessment.")
        for finding in asset.findings:
            lines += [
                "",
                f"#### [{_text(finding.priority.upper())}] {_text(finding.title)}",
                "",
                _text(finding.explanation),
                "",
                f"Action: {_text(finding.action)}",
                "",
                "Evidence:",
            ]
            for evidence in finding.evidence:
                reference = f" ({_text(evidence.reference)})" if evidence.reference else ""
                time = (
                    f" [{_text(evidence.observed_at.isoformat())}]" if evidence.observed_at else ""
                )
                lines.append(
                    f"- {_text(evidence.source)}: {_text(evidence.description)}{reference}{time}"
                )
        for context in asset.threat_context:
            lines += [
                "",
                f"#### Threat context: {_text(context.title)}",
                "",
                _text(context.description),
                "",
                f"Applicability: {_text(context.applicability)}",
                f"Action: {_text(context.action)}",
                f"Limitations: {_text(context.limitations)}",
                f"Rule: {_text(context.matched_rule_id)}",
                f"Source: {_text(context.source_name)} ({_text(context.source_url)}); "
                f"reviewed {_text(context.reviewed_at)}",
            ]
        for match in asset.indicator_matches:
            lines += [
                "",
                f"#### Indicator match [{_text(match.status.upper())}]",
                "",
                f"- {_text(match.indicator_type)}: `{_text(match.value)}` "
                f"(observed as {_text(match.observed_as)})",
                f"- Source: {_text(match.source_name)} ({_text(match.source_url)})",
                f"- Feed claim: {_text(match.description)}",
                f"- Valid: {_text(match.valid_from.isoformat())} "
                f"to {_text(match.valid_until.isoformat())}",
                "- Exact value match only; shared infrastructure and historical data "
                "can cause false positives.",
            ]
            for evidence in match.evidence:
                lines.append(
                    f"- Observation: {_text(evidence.source)}: {_text(evidence.description)}"
                )
    if report.warnings:
        lines += ["", "## Collection warnings", ""]
        lines.extend(f"- {_text(warning)}" for warning in report.warnings)
    lines += ["", "## Limitations", ""]
    lines.extend(f"- {_text(limitation)}" for limitation in report.limitations)
    return "\n".join(lines) + "\n"


def write_report(report: Report, snapshot: Snapshot, directory: Path) -> list[Path]:
    """Write all artifacts without overwriting existing files."""
    directory.mkdir(parents=True, exist_ok=True)
    targets = [directory / "report.json", directory / "report.md", directory / "observations.json"]
    existing = [str(path) for path in targets if path.exists() or path.is_symlink()]
    if existing:
        raise FileExistsError(f"Refusing to overwrite existing output: {', '.join(existing)}")
    content = [
        json.dumps(report.as_dict(), ensure_ascii=False, indent=2) + "\n",
        markdown(report),
        snapshot.model_dump_json(indent=2) + "\n",
    ]
    for path, text in zip(targets, content, strict=True):
        with path.open("x", encoding="utf-8") as handle:
            handle.write(text)
    return targets
