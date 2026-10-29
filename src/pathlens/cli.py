"""Command-line interface for live and offline analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from .analysis import analyze
from .collectors import CollectionError, collect_live
from .models import Snapshot, normalize_name
from .output import write_report

app = typer.Typer(no_args_is_help=True, help="Analyze public cloud asset clues with evidence.")


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="Domain you own or are authorized to assess.")],
    snapshot: Annotated[Path | None, typer.Option(help="Offline JSON source observations.")] = None,
    output: Annotated[Path, typer.Option(help="Directory for report files.")] = Path(
        "pathlens-output"
    ),
    rules: Annotated[Path | None, typer.Option(help="Optional YAML rules file.")] = None,
    max_assets: Annotated[
        int, typer.Option(min=1, max=200, help="Maximum number of in-scope names.")
    ] = 100,
    authorized: Annotated[
        bool, typer.Option(help="Confirm authorization for live public-source queries.")
    ] = False,
) -> None:
    """Analyze a domain using public sources or an offline snapshot."""
    try:
        domain = normalize_name(domain)
        if snapshot:
            if snapshot.stat().st_size > 25 * 1024 * 1024:
                raise ValueError("Snapshot exceeds 25 MiB")
            raw = Snapshot.model_validate_json(snapshot.read_text(encoding="utf-8"))
            if raw.domain != domain:
                raise ValueError("Snapshot domain does not match the requested domain")
            mode = "snapshot"
        else:
            raw = collect_live(domain, authorized=authorized, max_assets=max_assets)
            mode = "live"
        report = analyze(raw, max_assets=max_assets, rules_path=rules, collection_mode=mode)
        paths = write_report(report, raw, output)
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    findings = sum(len(asset.findings) for asset in report.assets)
    typer.echo(
        f"{len(report.assets)} assets, {findings} rule matches; candidates require manual review."
    )
    for asset in report.assets:
        path = " -> ".join(asset.cname_chain)
        typer.echo(f"[{asset.priority.upper()}] {path}")
        if asset.findings:
            top_finding = next(
                finding for finding in asset.findings if finding.priority == asset.priority
            )
            typer.echo(f"  {top_finding.title}: {top_finding.action}")
        else:
            typer.echo("  No matching rule; status is unknown, not a safety determination.")
    for path in paths:
        typer.echo(str(path))
    for warning in report.warnings:
        typer.echo(f"Warning: {warning}", err=True)


@app.command("mcp")
def run_mcp() -> None:
    """Run the MCP server over stdio."""
    from .mcp_server import main

    main()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
