"""Roll-ups shared by the API, the HTML report and the PDF: consolidated remediation plan and ATT&CK coverage."""
from __future__ import annotations

from typing import Any

from ..rules.policy import SEV_ORDER


def remediation_plan(tunnels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Each remediation once, with the rules/tunnels that need it, most severe first."""
    plan: dict[str, dict[str, Any]] = {}
    for p in tunnels:
        for f in p["findings"]:
            if f["category"] != "violation":
                continue
            r = plan.setdefault(f["remediation"]["id"], {**f["remediation"], "rules": set(), "tunnels": set(), "severity": f["severity"]})
            r["rules"].add(f["rule_id"])
            r["tunnels"].add(p["tunnel"]["id"])
            if SEV_ORDER[f["severity"]] < SEV_ORDER[r["severity"]]:
                r["severity"] = f["severity"]
    return sorted(({**v, "rules": sorted(v["rules"]), "tunnels": sorted(v["tunnels"])} for v in plan.values()),
                  key=lambda v: SEV_ORDER[v["severity"]])


def attack_rollup(tunnels: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Every ATT&CK technique the violation findings map to, with the tunnels it touches and its worst severity."""
    out: dict[str, dict[str, Any]] = {}
    for p in tunnels:
        for f in p["findings"]:
            if f["category"] != "violation":
                continue
            for m in f["mitre"]:
                e = out.setdefault(m["id"], {**m, "tunnels": set(), "severity": f["severity"]})
                e["tunnels"].add(p["tunnel"]["id"])
                if SEV_ORDER[f["severity"]] < SEV_ORDER[e["severity"]]:
                    e["severity"] = f["severity"]
    return sorted(({**v, "tunnels": len(v["tunnels"])} for v in out.values()), key=lambda v: (-v["tunnels"], SEV_ORDER[v["severity"]], v["id"]))
