"""Native Python CLI. Syft is an optional external SBOM generator."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .analysis import analyze
from .core import scan_sbom, sha256
from .database import fetch_database, validate_database
from .sbom import parse_sbom
from .word import write_word_report


def _json(text: str):
    return json.loads(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="seculens", description="SBOM assessment and evidence-based customer reports"
    )
    parser.add_argument("--version", action="version", version="0.1.0")
    commands = parser.add_subparsers(dest="command", required=True)
    sbom = commands.add_parser("sbom", help="Generate CycloneDX or SPDX JSON using Syft")
    sbom.add_argument("project", type=Path)
    sbom.add_argument("--format", choices=("cyclonedx", "spdx"), default="cyclonedx")
    sbom.add_argument("--syft", default="syft", help="Syft executable path")
    sbom.add_argument("-o", "--output", required=True, type=Path)
    scan = commands.add_parser("scan", help="Assess a JSON SBOM using OSV candidate records")
    scan.add_argument("sbom", type=Path)
    database = scan.add_mutually_exclusive_group(required=True)
    database.add_argument("--db", type=Path)
    database.add_argument(
        "--fetch-osv", action="store_true", help="Send package names/ecosystems to OSV"
    )
    scan.add_argument("--policy", type=Path)
    scan.add_argument("--source", type=Path, help="Run Python AST review rules")
    scan.add_argument("--customer", default="Customer")
    scan.add_argument("--lang", choices=("en", "ja"), default="en")
    scan.add_argument("-o", "--output", type=Path, default=Path("reports"))
    scan.add_argument("--fail-on-findings", action="store_true")
    opts = parser.parse_args(argv)
    try:
        if opts.command == "sbom":
            if not opts.project.is_dir():
                raise ValueError("Project must be a directory")
            output_format = "cyclonedx-json" if opts.format == "cyclonedx" else "spdx-json"
            result = subprocess.run(
                [opts.syft, "scan", f"dir:{opts.project.resolve()}", "-o", output_format],
                capture_output=True,
                text=True,
                check=True,
            )
            parse_sbom(_json(result.stdout))
            opts.output.parent.mkdir(parents=True, exist_ok=True)
            opts.output.write_text(result.stdout, encoding="utf-8")
            print(f"SBOM written to {opts.output}")
            return 0
        # Read every input before writing output evidence, even when paths overlap.
        input_text = opts.sbom.read_text(encoding="utf-8")
        parsed = parse_sbom(_json(input_text))
        if opts.db:
            database_text = opts.db.read_text(encoding="utf-8")
            records = validate_database(_json(database_text))
        else:
            print(
                "Fetching OSV candidates: package names and ecosystems are sent to api.osv.dev.",
                file=sys.stderr,
            )
            records = fetch_database(parsed["components"])
            database_text = json.dumps({"records": records}, ensure_ascii=False, indent=2) + "\n"
        policy = _json(opts.policy.read_text(encoding="utf-8")) if opts.policy else {}
        report = scan_sbom(
            input_text,
            records,
            customer=opts.customer,
            target=opts.sbom.name,
            policy=policy,
            database_source=opts.db.name if opts.db else "OSV API candidate snapshot",
            database_hash=sha256(database_text),
        )
        if opts.source:
            report["findings"].extend(analyze(opts.source))
        opts.output.mkdir(parents=True, exist_ok=True)
        (opts.output / "sbom.json").write_text(input_text, encoding="utf-8")
        (opts.output / "database.json").write_text(database_text, encoding="utf-8")
        (opts.output / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        write_word_report(report, opts.output / "report.docx", opts.lang)
        print(
            f"{len(parsed['components'])} components; {len(report['findings'])} findings. Reports: {opts.output}"
        )
        if opts.fail_on_findings and any(
            f["status"] in ("affected", "denied") or f["category"] == "security"
            for f in report["findings"]
        ):
            return 1
        return 2 if any(f["status"] == "unassessed" for f in report["findings"]) else 0
    except Exception as error:
        print(f"SecuLens: {error}", file=sys.stderr)
        return 2
