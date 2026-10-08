"""Independent ecosystem version comparisons against OSV affected ranges."""

from __future__ import annotations

import re
from typing import Any, Literal

from packaging.version import InvalidVersion
from packaging.version import Version as PepVersion
from semantic_version import Version as SemVersion

Match = Literal["affected", "not-affected", "unknown"]


def _canonical(name: str, ecosystem: str) -> str:
    return re.sub(r"[-_.]+", "-", name.lower()) if ecosystem == "PyPI" else name


def same_package(component: dict[str, Any], package: dict[str, Any]) -> bool:
    ecosystem = component.get("ecosystem")
    return ecosystem == package.get("ecosystem") and _canonical(
        component["name"], ecosystem
    ) == _canonical(package["name"], ecosystem)


def compare(left: str, right: str, ecosystem: str) -> int | None:
    try:
        if ecosystem == "PyPI":
            a, b = PepVersion(left), PepVersion(right)
        else:

            def normalize(text: str) -> str:
                # npm's semver library accepts a leading v (and = prefix).
                if ecosystem == "npm":
                    text = text.strip().lstrip("v=")
                elif ecosystem == "Packagist":
                    text = text.removeprefix("v")
                    if re.fullmatch(r"\d+\.\d+\.\d+\.0", text):
                        text = text[:-2]
                return text

            a, b = SemVersion(normalize(left)), SemVersion(normalize(right))
            # SemVer build metadata never affects precedence.
            a, b = a.truncate("prerelease"), b.truncate("prerelease")
        return (a > b) - (a < b)
    except (InvalidVersion, ValueError, TypeError):
        return None


def supported_version(component: dict[str, Any]) -> bool:
    version, ecosystem = component.get("version"), component.get("ecosystem")
    return bool(version and ecosystem and compare(version, version, ecosystem) is not None)


def match_record(component: dict[str, Any], record: dict[str, Any]) -> Match:
    if record.get("withdrawn"):
        return "not-affected"
    if not component.get("version") or not component.get("ecosystem"):
        return "unknown"
    version, ecosystem = component["version"], component["ecosystem"]
    unknown = False
    for affected in record["affected"]:
        if not same_package(component, affected["package"]):
            continue
        if any(
            v == version or compare(v, version, ecosystem) == 0
            for v in affected.get("versions", [])
        ):
            return "affected"
        ranges = affected.get("ranges", [])
        for version_range in ranges:
            if version_range["type"] not in ("SEMVER", "ECOSYSTEM"):
                if not any(r["type"] in ("SEMVER", "ECOSYSTEM") for r in ranges):
                    unknown = True
                continue
            active, uncertain = False, False
            for event in version_range["events"]:
                if "introduced" in event:
                    number = (
                        1
                        if event["introduced"] == "0"
                        else compare(version, event["introduced"], ecosystem)
                    )
                    if number is None:
                        uncertain = True
                    else:
                        active = number >= 0
                else:
                    end = event.get("fixed", event.get("limit", event.get("last_affected")))
                    if end is None:
                        uncertain = True
                        continue
                    number = compare(version, end, ecosystem)
                    if number is None:
                        uncertain = True
                        continue
                    included = number <= 0 if "last_affected" in event else number < 0
                    if active and included:
                        return "unknown" if uncertain else "affected"
                    active = False
            if active and not uncertain:
                return "affected"
            unknown = unknown or uncertain
        if not affected.get("versions") and not ranges:
            unknown = True
    return "unknown" if unknown else "not-affected"
