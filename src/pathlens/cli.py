"""Command-line interface for live and offline analysis."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from .analysis import analyze
from .collectors import CollectionError, collect_live
from .exposures import ExposureObservations, correlate_exposures
from .kev import Catalog, Observations, correlate, fetch_catalog, load_json
from .models import Snapshot, normalize_name
from .output import write_report
from .threat_intel import load_feed

app = typer.Typer(no_args_is_help=True, help="Analyze public cloud asset clues with evidence.")


@app.command()
def scan(
    domain: Annotated[str, typer.Argument(help="Domain you own or are authorized to assess.")],
    snapshot: Annotated[Path | None, typer.Option(help="Offline JSON source observations.")] = None,
    output: Annotated[Path, typer.Option(help="Directory for report files.")] = Path(
        "pathlens-output"
    ),
    rules: Annotated[Path | None, typer.Option(help="Optional YAML rules file.")] = None,
    threat_feed: Annotated[
        Path | None, typer.Option(help="Optional local indicator feed JSON.")
    ] = None,
    cve_observations: Annotated[
        Path | None, typer.Option(help="Explicit, authorized asset-CVE observations JSON.")
    ] = None,
    kev_catalog: Annotated[Path | None, typer.Option(help="CISA KEV catalog JSON.")] = None,
    exposure_observations: Annotated[
        Path | None, typer.Option(help="Minimal user-supplied exposure claims JSON.")
    ] = None,
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
        feed = load_feed(threat_feed) if threat_feed else None
        if bool(cve_observations) != bool(kev_catalog):
            raise ValueError("Provide both --cve-observations and --kev-catalog")
        observations = (
            Observations.model_validate(load_json(cve_observations)) if cve_observations else None
        )
        catalog = Catalog.model_validate(load_json(kev_catalog)) if kev_catalog else None
        exposures = (
            ExposureObservations.model_validate(load_json(exposure_observations))
            if exposure_observations
            else None
        )
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
        report = analyze(
            raw, max_assets=max_assets, rules_path=rules, collection_mode=mode, threat_feed=feed
        )
        if observations is not None and catalog is not None:
            correlate(report, observations, catalog)
        if exposures is not None:
            correlate_exposures(report, exposures)
        paths = write_report(report, raw, output)
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    findings = sum(len(asset.findings) for asset in report.assets)
    typer.echo(
        f"{len(report.assets)} assets, {findings} rule matches; candidates require manual review."
    )
    typer.echo(
        f"Threat feed: {report.threat_feed.status}, "
        f"{report.threat_feed.match_count} indicator matches."
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
        for match in asset.indicator_matches:
            typer.echo(
                f"  TI [{match.status}]: {match.indicator_type} {match.value} ({match.source_name})"
            )
        for match in asset.vulnerability_matches:
            typer.echo(f"  KEV: {match.cve_id}; supplied asset association requires verification.")
        for claim in asset.exposure_claims:
            typer.echo(f"  Exposure claim: {claim.category} ({claim.source_name}); unverified.")
    for path in paths:
        typer.echo(str(path))
    for warning in report.warnings:
        typer.echo(f"Warning: {warning}", err=True)


@app.command("validate-feed")
def validate_feed(path: Annotated[Path, typer.Argument(help="Local indicator feed JSON.")]) -> None:
    """Validate a local threat feed without loading or contacting its source."""
    try:
        feed = load_feed(path)
    except (ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Valid feed: {feed.source.name}, {len(feed.indicators)} indicators.")


@app.command("update-feodo")
def update_feodo(
    output: Annotated[Path, typer.Option(help="New output file; never overwritten.")],
) -> None:
    """Fetch Feodo's recommended IP list; no target domain is sent to the provider."""
    from .feodo import fetch_feodo

    try:
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        feed = fetch_feodo()
        with output.open("x", encoding="utf-8") as handle:
            handle.write(feed.model_dump_json(indent=2) + "\n")
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Saved {len(feed.indicators)} Feodo indicators to {output}.")


@app.command("watch-feodo")
def watch_feodo_command(
    directory: Annotated[Path, typer.Option(help="Existing output directory.")],
    interval: Annotated[int, typer.Option(min=300, help="Seconds between refreshes.")] = 3600,
    cycles: Annotated[int, typer.Option(min=0, help="0 runs until interrupted.")] = 0,
) -> None:
    """Refresh Feodo snapshots while this foreground process is running."""
    from .refresh import watch_feodo

    try:
        watch_feodo(directory, interval, cycles=cycles, notify=typer.echo)
    except KeyboardInterrupt:
        typer.echo("Stopped feed refresh.")
    except (ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


@app.command("update-kev")
def update_kev(
    output: Annotated[Path, typer.Option(help="New output file; never overwritten.")],
) -> None:
    """Fetch CISA's public KEV snapshot; no target domain is sent."""
    try:
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        catalog = fetch_catalog()
        with output.open("x", encoding="utf-8") as handle:
            handle.write(catalog.model_dump_json(indent=2) + "\n")
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Saved KEV catalog {catalog.catalogVersion} with {catalog.count} entries to {output}."
    )


@app.command("import-stix")
def import_stix_file(
    path: Annotated[Path, typer.Argument(help="STIX 2.1 bundle JSON.")],
    output: Annotated[Path, typer.Option(help="New output file; never overwritten.")],
    source_name: Annotated[str, typer.Option(help="Feed source name.")],
    source_url: Annotated[str, typer.Option(help="Feed source HTTPS URL.")],
) -> None:
    """Import the supported subset of STIX 2.1 indicators."""
    from .stix_import import import_stix
    from .threat_intel import Source

    try:
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        feed, skipped = import_stix(load_json(path), Source(name=source_name, url=source_url))
        with output.open("x", encoding="utf-8") as handle:
            handle.write(feed.model_dump_json(indent=2) + "\n")
    except (ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Imported {len(feed.indicators)} indicators; skipped {skipped} unsupported objects."
    )


@app.command("import-taxii")
def import_taxii(
    url: Annotated[str, typer.Option(help="Authorized TAXII 2.1 collection objects URL.")],
    output: Annotated[Path, typer.Option(help="New output file; never overwritten.")],
    source_name: Annotated[str, typer.Option(help="Feed source name.")],
) -> None:
    """Fetch an explicitly selected unauthenticated TAXII collection."""
    from .stix_import import import_stix
    from .taxii import fetch_collection
    from .threat_intel import Source

    try:
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        source = Source(name=source_name, url=url)
        feed, skipped = import_stix(fetch_collection(url), source)
        with output.open("x", encoding="utf-8") as handle:
            handle.write(feed.model_dump_json(indent=2) + "\n")
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(
        f"Imported {len(feed.indicators)} indicators; skipped {skipped} unsupported objects."
    )


@app.command("mcp")
def run_mcp() -> None:
    """Run the MCP server over stdio."""
    from .mcp_server import main

    main()


def main() -> None:
    app()


if __name__ == "__main__":
    main()
