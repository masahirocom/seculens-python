# Changelog

## 0.2.0

- Add customer report mode: cover, severity summary, findings register, numbered details, component table and page numbers.
- Add human-readable target and preparer options.
- Add traceable advisory severity, validated CVSS 3.0/3.1 base scoring, package-specific score selection and conservative alias severity consolidation.
- Preserve unknown / unsupported severity as Unrated; distinguish AST/license review from vulnerability severity.
- Extend report JSON to schema 1.1 with severity provenance and optional source-analysis execution metadata.

## 0.1.0

Initial native implementation: SPDX / CycloneDX JSON import, OSV matching, license policies, source analysis and Word / JSON reports.
