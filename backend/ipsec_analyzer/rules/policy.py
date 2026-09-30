"""YAML policy pack loader and validator."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

TIER_RANK = {"prohibited": 0, "deprecated": 1, "acceptable": 2, "recommended": 3}
SEVERITIES = ("critical", "high", "medium", "low", "info")
DEFAULT_POLICY = Path(__file__).resolve().parents[2] / "policy" / "nist_rfc8221.yaml"


class PolicyError(ValueError):
    """The policy pack is malformed."""


@dataclass
class Policy:
    raw: dict[str, Any]
    source: Path

    @property
    def name(self) -> str:
        return f"{self.raw['policy']['name']} v{self.raw['policy']['version']}"

    def tier(self, category: str, algorithm: str | None) -> str | None:
        """Tier of `algorithm` in `category`; None if unknown (unknown algorithms are never guessed)."""
        if algorithm is None:
            return None
        for tier, names in self.raw["tiers"][category].items():
            if algorithm in names:
                return tier
        return None

    def rank(self, category: str, algorithm: str | None) -> int | None:
        t = self.tier(category, algorithm)
        return None if t is None else TIER_RANK[t]

    @property
    def thresholds(self) -> dict[str, float]:
        return self.raw["thresholds"]

    @property
    def rules(self) -> list[dict[str, Any]]:
        return self.raw["rules"]

    def severity_weight(self, severity: str) -> float:
        return float(self.raw["severity_weight"][severity])


def load_policy(path: str | Path | None = None, known_checks: set[str] | None = None) -> Policy:
    p = Path(path) if path else DEFAULT_POLICY
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise PolicyError(f"cannot load policy {p}: {e}") from e
    for key in ("policy", "tiers", "thresholds", "severity_weight", "risk", "rules", "remediations", "mitre_catalog"):
        if key not in raw:
            raise PolicyError(f"policy missing top-level key '{key}'")
    for cat, tiers in raw["tiers"].items():
        for t in tiers:
            if t not in TIER_RANK:
                raise PolicyError(f"tiers.{cat}: unknown tier '{t}'")
    seen: set[str] = set()
    for r in raw["rules"]:
        rid = r.get("id")
        if not rid or rid in seen:
            raise PolicyError(f"missing or duplicate rule id: {rid!r}")
        seen.add(rid)
        if known_checks is not None and r.get("check") not in known_checks:
            raise PolicyError(f"rule {rid}: unknown check '{r.get('check')}'")
        for sev in list(r.get("severity_by_tier", {}).values()) + ([r["severity"]] if "severity" in r else []):
            if sev not in SEVERITIES:
                raise PolicyError(f"rule {rid}: unknown severity '{sev}'")
        if r.get("remediation") not in raw["remediations"]:
            raise PolicyError(f"rule {rid}: unknown remediation '{r.get('remediation')}'")
        for m in r.get("mitre", []):
            if m not in raw["mitre_catalog"]:
                raise PolicyError(f"rule {rid}: MITRE id {m} not in mitre_catalog")
    return Policy(raw, p)
