from __future__ import annotations

from typing import Any, Mapping

_SCHEMA_VERSION_V1 = "v1"
_EXPLOIT_VS_DETECT = {"exploit", "detect", "mixed", "unknown"}
_AUTH_REQUIREMENT = {"none", "optional", "required", "unknown"}


def build_report_v1(
    *,
    cve_id: str,
    year: int,
    template_path: str,
    signals: Mapping[str, Any],
) -> dict[str, Any]:
    normalized_signals: dict[str, Any] = dict(signals)
    normalized_signals.setdefault("severity", "unknown")
    normalized_signals.setdefault("version_constraints", [])
    normalized_signals.setdefault("feature_gates", [])

    report: dict[str, Any] = {
        "schema_version": _SCHEMA_VERSION_V1,
        "cve": {"id": cve_id, "year": year},
        "template": {"path": template_path},
        "signals": normalized_signals,
    }
    return report


def validate_report_v1(report: Mapping[str, Any]) -> None:
    version = report.get("schema_version")
    if version != _SCHEMA_VERSION_V1:
        raise ValueError(f"schema_version must be {_SCHEMA_VERSION_V1!r}")

    cve = _require_mapping(report, "cve", field="cve")
    _require_str(cve, "id", field="cve.id")
    _require_int(cve, "year", field="cve.year")

    template = _require_mapping(report, "template", field="template")
    _require_str(template, "path", field="template.path")

    signals = _require_mapping(report, "signals", field="signals")
    severity = _require_str(signals, "severity", field="signals.severity")
    if severity.strip() == "":
        raise ValueError("signals.severity must be non-empty")

    exploit_vs_detect = _require_str(signals, "exploit_vs_detect", field="signals.exploit_vs_detect")
    _require_one_of("signals.exploit_vs_detect", exploit_vs_detect, _EXPLOIT_VS_DETECT)

    auth_requirement = _require_str(signals, "auth_requirement", field="signals.auth_requirement")
    _require_one_of("signals.auth_requirement", auth_requirement, _AUTH_REQUIREMENT)

    oast_required = signals.get("oast_required")
    if not isinstance(oast_required, bool):
        raise ValueError("signals.oast_required must be boolean")

    _require_list_of_str(signals, "version_constraints", field="signals.version_constraints")
    _require_list_of_str(signals, "feature_gates", field="signals.feature_gates")


def _require_mapping(obj: Mapping[str, Any], key: str, *, field: str) -> Mapping[str, Any]:
    val = obj.get(key)
    if not isinstance(val, Mapping):
        raise ValueError(f"{field} must be an object")
    return val


def _require_str(obj: Mapping[str, Any], key: str, *, field: str) -> str:
    val = obj.get(key)
    if not isinstance(val, str):
        raise ValueError(f"{field} must be a string")
    return val


def _require_int(obj: Mapping[str, Any], key: str, *, field: str) -> int:
    val = obj.get(key)
    if not isinstance(val, int):
        raise ValueError(f"{field} must be an integer")
    return val


def _require_list_of_str(obj: Mapping[str, Any], key: str, *, field: str) -> list[str]:
    val = obj.get(key)
    if not isinstance(val, list):
        raise ValueError(f"{field} must be a list")
    for i, item in enumerate(val):
        if not isinstance(item, str):
            raise ValueError(f"{field}[{i}] must be a string")
    return val


def _require_one_of(field: str, value: str, allowed: set[str]) -> None:
    if value not in allowed:
        raise ValueError(f"{field} must be one of {sorted(allowed)!r}")
