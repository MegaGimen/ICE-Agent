"""Read-only applicability matching over an explicit, versioned advisory catalog.

This does not discover live software or run exploits. A match is not proof of compromise.
Vendor-specific/backported/prerelease version strings remain unknown unless normalized by a
trusted inventory adapter; a banner alone is not treated as verified installation evidence.
"""
from __future__ import annotations

import json
from pathlib import Path
import re


DEFAULT_CATALOG = Path(__file__).parent / "data/known_vulnerabilities.json"


def version(value):
    if not isinstance(value, str) or not re.fullmatch(r"v?\d+(?:\.\d+){1,3}", value):
        return None
    parts = tuple(int(p) for p in value.removeprefix("v").split("."))
    return parts + (0,) * (4 - len(parts))


def condition(expr, facts):
    """Return True/False/None plus unknown evidence fields; never treat missing as false."""
    if not expr:
        return True, []
    if "field" in expr:
        name = expr["field"]
        got = facts.get(name)
        return (got, []) if isinstance(got, bool) else (None, [name])
    if "version_gte" in expr:
        spec = expr["version_gte"]
        actual, boundary = version(facts.get(spec["field"])), version(spec["version"])
        if boundary is None:
            raise ValueError("invalid advisory version boundary")
        return (actual >= boundary, []) if actual is not None else (None, [spec["field"]])
    for operation in ("all", "any"):
        if operation in expr:
            values = [condition(child, facts) for child in expr[operation]]
            statuses = [x[0] for x in values]
            unknown = sorted({field for _, fields in values for field in fields})
            if operation == "all":
                result = False if False in statuses else (None if None in statuses else True)
            else:
                result = True if True in statuses else (None if None in statuses else False)
            return result, unknown
    raise ValueError("unsupported applicability condition")


def assess(inventory: list[dict], catalog: dict) -> dict:
    findings = []
    advisories = catalog["advisories"]
    for software in inventory:
        for advisory in advisories:
            if software.get("product") != advisory["product"]:
                continue
            actual = version(software.get("version"))
            if actual is None:
                affected = None
            else:
                outcomes = []
                for boundary in advisory["affected"]:
                    target = version(boundary["version"])
                    if target is None:
                        raise ValueError("invalid catalog version")
                    operators = {">=": actual >= target, ">": actual > target,
                                 "<=": actual <= target, "<": actual < target, "==": actual == target}
                    if boundary["op"] not in operators:
                        raise ValueError("unsupported version comparison")
                    outcomes.append(operators[boundary["op"]])
                affected = all(outcomes)
            prerequisites, unknown = condition(advisory.get("conditions"), software.get("conditions") or {})
            findings.append({
                "advisory_id": advisory["id"], "product": advisory["product"],
                "observed_version": software.get("version"),
                "version_status": "unknown" if affected is None else ("affected" if affected else "outside_affected_range"),
                "prerequisite_status": "unknown" if prerequisites is None else ("met" if prerequisites else "not_met"),
                "unknown_conditions": unknown,
                "inventory_assurance": software.get("assurance", "unverified"),
                "inventory_evidence": software.get("evidence_refs") or [],
                "observed_at": software.get("observed_at"),
                "scope": software.get("scope", "unspecified"),
                "fixed_version": advisory.get("fixed_version"), "source": advisory["source"],
                "catalog_checked_at": advisory.get("checked_at"),
                "exploitation_status": "not_determined_by_version_check",
            })
    return {"schema": "arena.vulnerability-assessment.v1", "catalog_version": catalog["catalog_version"],
            "catalog_coverage": catalog.get("coverage"), "software_observations": len(inventory),
            "findings": findings, "live_scan_performed": False,
            "note": "No matching entry means no finding in this catalog, not that the host is safe. False prerequisites do not mean the vulnerable code was patched."}


def assess_file(inventory_path: Path, catalog_path: Path = DEFAULT_CATALOG):
    raw = json.loads(inventory_path.read_text())
    inventory = raw["software"] if isinstance(raw, dict) else raw
    if not isinstance(inventory, list):
        raise ValueError("inventory must contain a software list")
    return assess(inventory, json.loads(catalog_path.read_text()))
