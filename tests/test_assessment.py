import copy
import json
from pathlib import Path
from zipfile import ZipFile

import pytest
from docx import Document

from seculens import evaluate_license, match_record, parse_sbom, scan_sbom, write_word_report
from seculens.matcher import compare

ROOT = Path(__file__).resolve().parents[1]


def record(events=None, *, ecosystem="npm", name="demo", versions=None, kind="SEMVER"):
    affected = {"package": {"ecosystem": ecosystem, "name": name}}
    if events is not None:
        affected["ranges"] = [{"type": kind, "events": events}]
    if versions is not None:
        affected["versions"] = versions
    return {"id": "TEST-1", "affected": [affected]}


def component(version="1.0.0", *, ecosystem="npm", name="demo"):
    return {"ecosystem": ecosystem, "name": name, "version": version}


@pytest.mark.parametrize("format", ["cyclonedx", "spdx"])
def test_formats_and_deterministic_evidence(format):
    text = (ROOT / f"examples/{format}.json").read_text()
    records = json.loads((ROOT / "examples/database.json").read_text())
    if isinstance(records, dict):
        records = records["records"]
    kwargs = dict(created_at="2026-01-01T00:00:00.000Z", policy={"allow": ["MIT", "Apache-2.0"]})
    report = scan_sbom(text, records, **kwargs)
    assert report == scan_sbom(text, records, **kwargs)
    assert len(report["sbom"]["components"]) == 3
    assert len([f for f in report["findings"] if f["category"] == "vulnerability"]) == 1
    assert all(c["status"] != "unassessed" for c in report["checks"])
    assert len(report["sbomSha256"]) == 64


@pytest.mark.parametrize(
    "version,result",
    [
        ("0.9.9", "not-affected"),
        ("1.0.0", "affected"),
        ("1.9.9", "affected"),
        ("2.0.0", "not-affected"),
        ("3.0.0", "affected"),
        ("4.0.0", "not-affected"),
    ],
)
def test_multiple_intervals(version, result):
    advisory = record(
        [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}, {"introduced": "3.0.0"}, {"limit": "4.0.0"}]
    )
    assert match_record(component(version), advisory) == result


def test_inclusive_endpoint_and_git_coverage():
    assert (
        match_record(component("2.0.0"), record([{"introduced": "0"}, {"last_affected": "2.0.0"}]))
        == "affected"
    )
    git = record([{"introduced": "abc"}], kind="GIT")
    assert match_record(component(), git) == "unknown"
    git["affected"][0]["ranges"].append({"type": "SEMVER", "events": [{"introduced": "2.0.0"}]})
    assert match_record(component(), git) == "not-affected"
    assert match_record(component(), record([{"introduced": "branch"}])) == "unknown"


def test_withdrawn_and_pep440_name_normalization():
    advisory = record(versions=["1.0"], ecosystem="PyPI", name="My_Package")
    assert (
        match_record(component("1.0.0", ecosystem="PyPI", name="my-package"), advisory)
        == "affected"
    )
    advisory["withdrawn"] = "2026-01-01T00:00:00Z"
    assert (
        match_record(component("1.0", ecosystem="PyPI", name="my-package"), advisory)
        == "not-affected"
    )
    assert compare("1.0rc1", "1.0", "PyPI") == -1
    assert compare("1.0.post1", "1.0", "PyPI") == 1
    assert compare("1.0.0+build", "1.0.0", "npm") == 0
    assert compare("v1.0.0.0", "1.0.0", "Packagist") == 0
    assert compare("dev-main", "1.0.0", "Packagist") is None


@pytest.mark.parametrize(
    "expression,decision",
    [
        ("MIT", "allowed"),
        ("MIT OR GPL-3.0-only", "allowed"),
        ("MIT AND GPL-3.0-only", "denied"),
        ("Apache-2.0 AND MIT", "allowed"),
        ("MIT WITH LLVM-exception", "review"),
        ("LicenseRef-Customer", "review"),
        ("NOASSERTION", "review"),
        ("MIT AND", "review"),
    ],
)
def test_license_expressions(expression, decision):
    assert (
        evaluate_license(expression, {"allow": ["MIT", "Apache-2.0"], "deny": ["GPL-3.0-only"]})
        == decision
    )
    assert (
        evaluate_license("MIT WITH LLVM-exception", {"allow": ["MIT WITH LLVM-exception"]})
        == "allowed"
    )


def test_alias_consolidation_is_transitive_and_per_component():
    data = json.loads((ROOT / "examples/cyclonedx.json").read_text())
    base = record([{"introduced": "0"}], name="lodash")
    records = [
        dict(base, id="A", aliases=["B"]),
        dict(base, id="C", aliases=["D"]),
        dict(base, id="B", aliases=["C"]),
    ]
    report = scan_sbom(json.dumps(data), records)
    vulnerabilities = [f for f in report["findings"] if f["category"] == "vulnerability"]
    assert len(vulnerabilities) == 1
    assert vulnerabilities[0]["aliases"] == ["B", "C", "D"]


def test_missing_identity_invalid_version_and_duplicate_ids():
    data = json.loads((ROOT / "examples/cyclonedx.json").read_text())
    data["components"][0].pop("purl")
    data["components"][1]["version"] = "bad-version"
    data["components"][1]["purl"] = "pkg:pypi/requests@bad-version"
    report = scan_sbom(json.dumps(data), [])
    assert sum(c["status"] == "unassessed" for c in report["checks"]) == 2
    duplicate = copy.deepcopy(data["components"][0])
    data["components"].append(duplicate)
    with pytest.raises(ValueError, match="Duplicate"):
        parse_sbom(data)
    with pytest.raises(ValueError):
        scan_sbom(json.dumps(data), [], policy=[])


def test_native_word_japanese_font_and_links(tmp_path):
    text = (ROOT / "examples/cyclonedx.json").read_text()
    advisory = dict(
        record([{"introduced": "0"}], name="lodash"),
        references=[{"url": "https://example.com/advisory"}],
    )
    report = scan_sbom(text, [advisory], customer="テスト顧客")
    output = tmp_path / "report.docx"
    write_word_report(report, output, "ja")
    document = Document(output)
    assert "テスト顧客" in "\n".join(p.text for p in document.paragraphs)
    with ZipFile(output) as archive:
        assert "word/fonts/seculens.odttf" in archive.namelist()
        assert b"embedRegular" in archive.read("word/fontTable.xml")
        assert b"https://example.com/advisory" in archive.read("word/_rels/document.xml.rels")
