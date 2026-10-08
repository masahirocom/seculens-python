"""Local OSV snapshots and explicit candidate download without version filtering."""

from __future__ import annotations

from typing import Any

import requests


def validate_database(data: Any) -> list[dict[str, Any]]:
    records = (
        data if isinstance(data, list) else data.get("records") if isinstance(data, dict) else None
    )
    if not isinstance(records, list):
        raise ValueError("Database must be an OSV record array or { records: [...] }")
    for record in records:
        if (
            not isinstance(record, dict)
            or not isinstance(record.get("id"), str)
            or not isinstance(record.get("affected"), list)
        ):
            raise ValueError("Invalid OSV record")
        for affected in record["affected"]:
            package = affected.get("package", {})
            if not all(isinstance(package.get(key), str) for key in ("name", "ecosystem")):
                raise ValueError(f"Invalid affected package in {record['id']}")
            if not isinstance(affected.get("versions", []), list) or any(
                not isinstance(v, str) for v in affected.get("versions", [])
            ):
                raise ValueError(f"Invalid versions in {record['id']}")
            for version_range in affected.get("ranges", []):
                if not isinstance(version_range.get("type"), str) or not isinstance(
                    version_range.get("events"), list
                ):
                    raise ValueError(f"Invalid range in {record['id']}")
                for event in version_range["events"]:
                    if not isinstance(event, dict) or any(
                        not isinstance(v, str) for v in event.values()
                    ):
                        raise ValueError(f"Invalid event in {record['id']}")
    return records


def fetch_database(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    seen: set[tuple[str, str]] = set()
    with requests.Session() as session:
        for component in components:
            ecosystem = component.get("ecosystem")
            if not ecosystem:
                continue
            key = ecosystem, component["name"]
            if key in seen:
                continue
            seen.add(key)
            token: str | None = None
            tokens: set[str] = set()
            while True:
                body: dict[str, Any] = {
                    "package": {"name": component["name"], "ecosystem": ecosystem}
                }
                if token:
                    body["page_token"] = token
                response = session.post("https://api.osv.dev/v1/query", json=body, timeout=30)
                response.raise_for_status()
                data = response.json()
                for record in validate_database(data.get("vulns", [])):
                    records[record["id"]] = record
                token = data.get("next_page_token")
                if not token:
                    break
                if token in tokens:
                    raise ValueError("Repeated OSV pagination token")
                tokens.add(token)
    return [records[key] for key in sorted(records)]
