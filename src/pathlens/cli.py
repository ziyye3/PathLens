"""Command-line interface for live and offline analysis."""

from __future__ import annotations

import importlib.util
import json
import os
import uuid
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError

from .analysis import analyze
from .collectors import CollectionError, collect_live
from .exposures import ExposureObservations, correlate_exposures
from .kev import (
    Catalog,
    Observations,
    ProductObservations,
    correlate,
    correlate_products,
    fetch_catalog,
    load_json,
)
from .models import Snapshot, in_scope, normalize_name
from .osv import OSVSnapshot, PackageObservations, correlate_osv, fetch_observations
from .output import write_report
from .threat_intel import load_feed

app = typer.Typer(no_args_is_help=True, help="Analyze public cloud asset clues with evidence.")


def _write_private(path: Path, content: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(content)


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
    product_observations: Annotated[
        Path | None, typer.Option(help="User-supplied asset/product observations JSON.")
    ] = None,
    fetch_kev: Annotated[
        bool, typer.Option(help="Fetch the CISA KEV catalog; does not send the target domain.")
    ] = False,
    exposure_observations: Annotated[
        Path | None, typer.Option(help="Minimal user-supplied exposure claims JSON.")
    ] = None,
    osv_observations: Annotated[
        Path | None, typer.Option(help="User-supplied asset/package/version observations JSON.")
    ] = None,
    osv_results: Annotated[
        Path | None, typer.Option(help="Offline OSV query results JSON.")
    ] = None,
    fetch_osv: Annotated[
        bool, typer.Option(help="Send package names and versions (not domains) to OSV.")
    ] = False,
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
        if fetch_kev and kev_catalog:
            raise ValueError("Choose either --fetch-kev or --kev-catalog")
        if bool(cve_observations or product_observations) != bool(kev_catalog or fetch_kev):
            raise ValueError("Provide CVE or product observations and a KEV catalog source")
        observations = (
            Observations.model_validate(load_json(cve_observations)) if cve_observations else None
        )
        products = (
            ProductObservations.model_validate(load_json(product_observations))
            if product_observations
            else None
        )
        catalog = (
            fetch_catalog()
            if fetch_kev
            else (Catalog.model_validate(load_json(kev_catalog)) if kev_catalog else None)
        )
        exposures = (
            ExposureObservations.model_validate(load_json(exposure_observations))
            if exposure_observations
            else None
        )
        if fetch_osv and osv_results:
            raise ValueError("Choose either --fetch-osv or --osv-results")
        if bool(osv_observations) != bool(osv_results or fetch_osv):
            raise ValueError("Provide OSV observations and either --fetch-osv or --osv-results")
        packages = (
            PackageObservations.model_validate(load_json(osv_observations))
            if osv_observations
            else None
        )
        if packages is not None and any(
            not in_scope(item.asset, domain) for item in packages.observations
        ):
            raise ValueError("Package observation asset is outside the requested domain")
        osv_snapshot = OSVSnapshot.model_validate(load_json(osv_results)) if osv_results else None
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
        if products is not None and catalog is not None:
            correlate_products(report, products, catalog)
        if exposures is not None:
            correlate_exposures(report, exposures)
        if packages is not None:
            if fetch_osv:
                osv_snapshot = fetch_observations(packages)
            if osv_snapshot is not None:
                correlate_osv(
                    report, packages, osv_snapshot, provenance="live" if fetch_osv else "supplied"
                )
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
        for candidate in asset.product_kev_candidates:
            typer.echo(f"  Product/KEV candidate: {candidate.cve_id}; version is not verified.")
        for claim in asset.exposure_claims:
            typer.echo(f"  Exposure claim: {claim.category} ({claim.source_name}); unverified.")
        for match in asset.osv_matches:
            status = "withdrawn" if match.withdrawn else "returned"
            typer.echo(
                f"  OSV [{status}/{report.osv_correlation.status}]: {match.advisory_id}; "
                "deployment is unverified."
            )
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


@app.command("make-launch-agent")
def make_launch_agent_command(
    output: Annotated[Path, typer.Option(help="New plist file; not installed automatically.")],
    directory: Annotated[Path, typer.Option(help="Existing absolute feed directory.")],
    python: Annotated[Path, typer.Option(help="Absolute Python path in the PathLens environment.")],
    interval: Annotated[int, typer.Option(min=300, help="Seconds between refreshes.")] = 3600,
) -> None:
    """Generate a macOS launch agent; does not register or start it."""
    from .launch_agent import write_launch_agent

    try:
        write_launch_agent(output, python, directory, interval)
    except (ValueError, OSError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Wrote {output}; not registered or started.")


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


@app.command("evaluate-stix")
def evaluate_stix_command(
    indicators: Annotated[Path, typer.Argument(help="STIX 2.1 indicator bundle JSON.")],
    observations: Annotated[Path, typer.Argument(help="STIX 2.1 observed-data bundle JSON.")],
    output: Annotated[Path | None, typer.Option(help="New JSON result file.")] = None,
    snapshot: Annotated[
        bool, typer.Option(help="Treat observations as an offline PathLens snapshot.")
    ] = False,
    indicator_id: Annotated[
        list[str] | None, typer.Option(help="Select an indicator ID; repeat for multiple IDs.")
    ] = None,
) -> None:
    """Evaluate complex STIX patterns against explicitly supplied observations."""
    from .stix_patterns import evaluate_stix, snapshot_observations

    try:
        if any(importlib.util.find_spec(name) is None for name in ("stix2matcher", "psutil")):
            raise ValueError(
                "Install STIX support from the PathLens checkout: pip install -e '.[stix]'"
            )
        if output is not None and (output.exists() or output.is_symlink()):
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        observed = load_json(observations)
        source_indexes = None
        if snapshot:
            observed, source_indexes = snapshot_observations(Snapshot.model_validate(observed))
        result = evaluate_stix(load_json(indicators), observed, indicator_ids=indicator_id)
        if source_indexes is not None:
            result["snapshot_dns_record_indexes"] = source_indexes
        rendered = json.dumps(result, indent=2, ensure_ascii=False) + "\n"
        if output is None:
            typer.echo(rendered, nl=False)
        else:
            _write_private(output, rendered)
    except (ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc


def _prompt_taxii_auth(auth_method: str) -> tuple[tuple[str, str] | None, str | None]:
    if auth_method == "basic":
        username = typer.prompt("TAXII username")
        password = typer.prompt("TAXII password", hide_input=True)
        return (username, password), None
    if auth_method == "bearer":
        return None, typer.prompt("TAXII bearer token", hide_input=True)
    if auth_method != "none":
        raise ValueError("Authentication must be none, basic, or bearer")
    return None, None


@app.command("check-taxii")
def check_taxii(
    url: Annotated[str, typer.Option(help="Authorized TAXII 2.1 collection objects URL.")],
    auth_method: Annotated[
        str, typer.Option(help="Authentication: none, basic, or bearer.")
    ] = "none",
) -> None:
    """Check access to one page without saving or printing threat data."""
    from .taxii import check_collection, validate_collection_url

    try:
        validate_collection_url(url)
        basic, bearer = _prompt_taxii_auth(auth_method)
        count, more = check_collection(url, basic_auth=basic, bearer_token=bearer)
    except (CollectionError, ValueError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    typer.echo(f"Collection accessible; received {count} objects; more pages: {more}.")
    typer.echo("Access success alone does not prove the server enforced authentication.")


@app.command("import-taxii")
def import_taxii(
    url: Annotated[str, typer.Option(help="Authorized TAXII 2.1 collection objects URL.")],
    output: Annotated[Path, typer.Option(help="New output file; never overwritten.")],
    source_name: Annotated[str, typer.Option(help="Feed source name.")],
    auth_method: Annotated[
        str, typer.Option(help="Authentication: none, basic, or bearer.")
    ] = "none",
    raw_stix: Annotated[
        bool, typer.Option(help="Save the unmarked original STIX bundle for pattern evaluation.")
    ] = False,
) -> None:
    """Fetch an explicitly selected TAXII collection; credentials are prompted privately."""
    from .stix_import import import_stix
    from .taxii import fetch_collection, validate_collection_url
    from .threat_intel import Source

    try:
        if output.exists() or output.is_symlink():
            raise FileExistsError(f"Refusing to overwrite existing output: {output}")
        source = Source(name=source_name, url=url)
        validate_collection_url(url)
        basic, bearer = _prompt_taxii_auth(auth_method)
        document = fetch_collection(url, basic_auth=basic, bearer_token=bearer)
        if raw_stix:
            if any(
                not isinstance(obj, dict)
                or obj.get("object_marking_refs") or obj.get("granular_markings")
                for obj in document["objects"]
            ):
                raise ValueError("Marked or invalid STIX content cannot be saved as raw output")
            document["id"] = f"bundle--{uuid.uuid4()}"
            serialized = json.dumps(document, indent=2, ensure_ascii=False) + "\n"
            if len(serialized.encode("utf-8")) > 25 * 1024 * 1024:
                raise ValueError("Raw STIX bundle exceeds 25 MiB")
            _write_private(output, serialized)
        else:
            feed, skipped = import_stix(document, source)
            with output.open("x", encoding="utf-8") as handle:
                handle.write(feed.model_dump_json(indent=2) + "\n")
    except (CollectionError, ValueError, OSError, ValidationError) as exc:
        typer.echo(f"Error: {exc}", err=True)
        raise typer.Exit(code=1) from exc
    if raw_stix:
        typer.echo(f"Saved {len(document['objects'])} original objects to a private local file.")
    else:
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
