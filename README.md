# SecuLens for Python

Independent Python implementation of SecuLens: assess SPDX / CycloneDX JSON SBOMs against OSV records, apply SPDX license-expression policies, review Python ASTs, and produce customer-facing Word and JSON reports. Python 3.10+; no Node.js or Trivy runtime required.

This is an early release, not a complete SAST or legal compliance determination. A vulnerability match is evidence from the supplied advisory snapshot; a security AST finding is a review candidate.

## Install

Until PyPI publication, install the wheel from [GitHub releases](https://github.com/masahirocom/seculens-python/releases). For development:

```sh
python -m venv .venv
# Activate your virtual environment, then:
pip install -e '.[dev]'
seculens --version
```

## Quick start (offline)

```sh
seculens scan examples/cyclonedx.json --db examples/database.json \
  --policy examples/policy.json --source examples \
  --customer "Sample Customer" --lang ja --output reports/sample
```

`examples/database.json` is synthetic demonstration data, not a production vulnerability database. Outputs are `report.docx`, `report.json`, `sbom.json`, and `database.json`. Japanese Word reports embed the bundled Noto Sans JP font under the SIL Open Font License.

Download current OSV candidates explicitly:

```sh
seculens scan bom.json --fetch-osv --policy examples/policy.json --output reports/live
```

Only package names and ecosystems are sent to `api.osv.dev`; matching is performed locally. Use `--db` for offline assessment. Pagination, withdrawn records, version ranges, advisory aliases, unsupported identities and incomplete ranges are accounted for. `no-match` never means vulnerability-free. Evidence hashes identify the exact SBOM and database text used.

## Generate SBOMs

Install [Syft](https://github.com/anchore/syft) separately, then:

```sh
seculens sbom ./project --format cyclonedx --output bom.cdx.json
seculens sbom ./project --format spdx --output bom.spdx.json
```

`--syft /path/to/syft` selects an executable. SecuLens validates its output. Existing CycloneDX 1.4–1.7 JSON or SPDX 2.2/2.3 JSON can also be imported directly. Package URLs identify npm, PyPI and Packagist dependencies regardless of which language implementation runs the assessment. SPDX 3 and XML are not supported yet.

## License policy

```json
{"allow": ["MIT", "Apache-2.0", "BSD-3-Clause"], "deny": ["GPL-3.0-only"]}
```

SPDX `AND` requires all branches to be allowed; `OR` accepts an allowed option. `WITH` exceptions require an exact policy entry. Unrecognized or missing expressions require review. This evaluates the configured policy, not every legal obligation or regulatory framework.

## Python analysis

`--source` parses `.py` files without importing or executing them. Rules review `eval` / `exec`, OS shell calls, `subprocess` with literal `shell=True`, pickle deserialization and YAML loading without an explicit safe loader. Complexity review triggers above cyclomatic 10 or nesting 4. Imports and aliases are recognized syntactically; shadowing, dynamic aliases, data flow and exploitability are not resolved. Syntax errors become coverage findings. Virtual environments, dependency/build directories and symlinks are skipped. JS/TS source analysis belongs to the [TypeScript implementation](https://github.com/masahirocom/seculens); PHP implementation is planned.

## Exit status and API

- `0`: assessment completed (findings may exist).
- `1`: `--fail-on-findings` and a vulnerability, denied license or security review candidate exists.
- `2`: incomplete coverage or an operational error; status 1 takes precedence when requested.

```python
from seculens import scan_sbom, write_word_report

report = scan_sbom(sbom_text, records, policy={"allow": ["MIT"]}, customer="Customer")
write_word_report(report, "report.docx", language="ja")
```

Schema `1.0` is shared with the TypeScript implementation. Advisory matching supports PyPI PEP 440, npm SemVer and stable numeric Composer versions / SemVer prereleases; Composer branches and Git commit ranges can remain unassessed. Full CVSS prioritization, reachability, container/OS scanning and full SAST are future work. Reports do not claim those checks were performed.

## Validation

```sh
pytest
ruff check .
ruff format --check .
pip-audit
python -m build
python -m twine check dist/*
```

See [security policy](SECURITY.md). Apache-2.0 code; bundled Japanese font is SIL OFL. [NOTICE](NOTICE) identifies third-party assets.
