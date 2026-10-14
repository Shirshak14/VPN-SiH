"""Before/after comparison of two analyses (e.g. a gateway capture before and after applying the remediation plan).

Tunnels are matched by their peer pair (initiator, responder). Several tunnels between the same peers (retries, rekeys)
are paired highest-risk first; any left over are reported as only-before / only-after.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from ..rules.policy import SEV_ORDER


def _rules(payload: dict[str, Any]) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}
    for f in payload["findings"]:
        if f["category"] == "violation":
            cur = out.get(f["rule_id"])
            if cur is None or SEV_ORDER[f["severity"]] < SEV_ORDER[cur["severity"]]:
                out[f["rule_id"]] = {"rule_id": f["rule_id"], "title": f["title"], "severity": f["severity"]}
    return out


def _side(payload: dict[str, Any]) -> dict[str, Any]:
    t = payload["tunnel"]
    return {"id": t["id"], "score": payload["risk"]["score"], "band": payload["risk"]["band"],
            "suite": (t.get("chosen") or {}).get("label"), "rules": sorted(_rules(payload))}


def _summary(payloads: list[dict[str, Any]]) -> dict[str, Any]:
    top = max(payloads, key=lambda p: p["risk"]["score"], default=None)
    bands: dict[str, int] = defaultdict(int)
    for p in payloads:
        bands[p["risk"]["band"]] += 1
    return {"tunnels": len(payloads), "max_score": top["risk"]["score"] if top else None, "max_band": top["risk"]["band"] if top else None,
            "violations": sum(f["category"] == "violation" for p in payloads for f in p["findings"]), "with_violations": sum(1 for p in payloads if _rules(p)),
            "bands": dict(bands)}


def compare(before: list[dict[str, Any]], after: list[dict[str, Any]]) -> dict[str, Any]:
    rb: dict[str, dict[str, str]] = {}
    ra: dict[str, dict[str, str]] = {}
    for src, dst in ((before, rb), (after, ra)):
        for p in src:
            for k, v in _rules(p).items():
                if k not in dst or SEV_ORDER[v["severity"]] < SEV_ORDER[dst[k]["severity"]]:
                    dst[k] = v
    by_sev = lambda d: sorted(d, key=lambda r: (SEV_ORDER[r["severity"]], r["rule_id"]))  # noqa: E731

    groups: dict[tuple[str, str], tuple[list, list]] = defaultdict(lambda: ([], []))
    for i, side in enumerate((before, after)):
        for p in sorted(side, key=lambda p: -p["risk"]["score"]):
            groups[(p["tunnel"]["initiator"], p["tunnel"]["responder"])][i].append(p)
    rows = []
    for (ini, resp), (bs, as_) in groups.items():
        for j in range(max(len(bs), len(as_))):
            b = _side(bs[j]) if j < len(bs) else None
            a = _side(as_[j]) if j < len(as_) else None
            rows.append({"initiator": ini, "responder": resp, "before": b, "after": a,
                         "delta": round(a["score"] - b["score"], 1) if a and b else None,
                         "fixed": sorted(set(b["rules"]) - set(a["rules"])) if a and b else [],
                         "new": sorted(set(a["rules"]) - set(b["rules"])) if a and b else []})
    # matched pairs first, biggest improvement first; then unmatched, highest risk first
    rows.sort(key=lambda r: (0, r["delta"]) if r["delta"] is not None else (1, -(r["before"] or r["after"])["score"]))
    return {"before": _summary(before), "after": _summary(after),
            "rules": {"fixed": by_sev(v for k, v in rb.items() if k not in ra),
                      "new": by_sev(v for k, v in ra.items() if k not in rb),
                      "remaining": by_sev(v for k, v in ra.items() if k in rb)},
            "tunnels": rows}
