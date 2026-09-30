"""Evaluation harness: produces every metric quoted in the README from labelled captures.

    python -m ipsec_analyzer.evaluation --manifest ../data/captures/manifest.json

Three evidence classes are reported separately and never blended:
  * synthetic corpus   - detection metrics + parse accuracy (ground truth = the generator's spec)
  * real-public        - parser validated against independent oracles (Wireshark expected values, Scapy)
  * throughput         - parser/pipeline speed on the corpus
"""
from __future__ import annotations

import argparse
import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ml.model import DEFAULT_MODEL, AnomalyModel
from .parser import parse_pcap
from .parser.decrypt import load_key_table
from .pipeline import analyze
from .rules import RuleEngine

ALERT_RISK = 15.0  # rules-only risk at/above the policy's "medium" band (i.e. at least one medium finding)


def _prf(tp: int, fp: int, fn: int, tn: int) -> dict[str, Any]:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else None
    fpr = fp / (fp + tn) if fp + tn else None
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": p, "recall": r, "f1": f1, "false_positive_rate": fpr}


# ---------------------------------------------------------------------------------- synthetic
_V1_ENC = {"AES_CBC": "AES_CBC", "3DES": "3DES_CBC", "DES": "DES_CBC"}
_V1_HASH = {"HMAC_MD5_96": "MD5", "HMAC_SHA1_96": "SHA1", "HMAC_SHA2_256_128": "SHA2_256",
            "HMAC_SHA2_384_192": "SHA2_384", "HMAC_SHA2_512_256": "SHA2_512"}


def _v1_label(spec_label: str) -> str:
    enc, integ, dh = spec_label.split("/")
    e, _, bits = enc.partition("-")
    return "/".join([_V1_ENC[e] + (f"-{bits}" if bits else ""), _V1_HASH[integ], dh])


def evaluate_synthetic(manifest_path: Path, model: AnomalyModel | None, use_keys: bool = True) -> dict[str, Any]:
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    engine = RuleEngine()
    counts = {k: [0, 0, 0, 0] for k in ("combined", "rules", "ml")}  # tp fp fn tn
    fam: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    rule_tp = rule_fp = rule_fn = 0
    per_rule: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    parse_checks: dict[str, list[int]] = defaultdict(lambda: [0, 0])  # name -> [ok, total]
    missed: list[dict[str, Any]] = []
    false_alarms: list[dict[str, Any]] = []
    n_tunnels = 0

    def chk(name: str, ok: bool) -> None:
        parse_checks[name][1] += 1
        parse_checks[name][0] += int(ok)

    for name, m in manifest.items():
        if m["split"] in ("train", "demo"):
            continue  # held-out test split only
        keys = root / m["keys"] if (use_keys and m.get("keys")) else None
        res = analyze(root / m["file"], keys, engine, model)
        by = {r.tunnel.ispi: r for r in res.tunnels}
        chk("ike_datagrams_parsed", res.capture.stats.ike_messages == sum(t["ike_datagrams"] for t in m["tunnels"]))
        chk("esp_packets_parsed", res.capture.stats.esp_packets == sum(t["esp_datagrams"] for t in m["tunnels"]))
        for tr in m["tunnels"]:
            r = by.get(tr["ispi"])
            chk("tunnel_reconstructed", r is not None)
            if r is None:
                continue
            n_tunnels += 1
            t = r.tunnel
            chk("ike_version", t.ike_version == tr["ike_version"])
            if tr["negotiated_ike"]:
                want = tr["negotiated_ike"] if tr["ike_version"] == 2 else _v1_label(tr["negotiated_ike"])
                chk("ike_suite", t.chosen is not None and t.chosen.label() == want)
            else:
                chk("ike_suite", t.chosen is None)  # nothing was negotiated -> nothing should be reported
            if tr["ike_version"] == 2 and use_keys and tr["negotiated_esp"]:
                chk("auth_method", t.auth_method == ("RSA Digital Signature" if tr["auth"] == "RSA" else "Shared Key Message Integrity Code"))
                chk("child_sa_suite", bool(t.child_sas) and t.child_sas[0].suite.label() == tr["negotiated_esp"])
            # detection
            positive = tr["label"] != "benign"
            rules_alert = r.risk.rules_component * 100 >= ALERT_RISK
            ml_alert = bool(r.anomaly and r.anomaly["is_anomalous"])
            alert = {"combined": rules_alert or ml_alert, "rules": rules_alert, "ml": ml_alert}
            for k, a in alert.items():
                i = (0 if a else 2) if positive else (1 if a else 3)
                counts[k][i] += 1
            f = fam[tr["family"]]
            f["n"] += 1
            f["combined"] += alert["combined"]
            f["rules"] += rules_alert
            f["ml"] += ml_alert
            if positive and not alert["combined"]:
                missed.append({"capture": name, "family": tr["family"], "risk": r.risk.score})
            if not positive and alert["combined"]:
                false_alarms.append({"capture": name, "family": tr["family"], "risk": r.risk.score,
                                     "rules": [x.rule_id for x in r.findings if x.category == "violation"],
                                     "anomaly": r.anomaly["score"] if r.anomaly else None})
            # rule-level
            got = {x.rule_id for x in r.findings if x.category == "violation"}
            want_r = set(tr["assessable_rules"])
            rule_tp += len(got & want_r)
            rule_fp += len(got - want_r)
            rule_fn += len(want_r - got)
            for rid in got | want_r:
                per_rule[rid][0] += rid in got and rid in want_r
                per_rule[rid][1] += rid in got and rid not in want_r
                per_rule[rid][2] += rid not in got and rid in want_r

    return {
        "keys_provided": use_keys,
        "tunnels_evaluated": n_tunnels,
        "detection": {k: _prf(*v) for k, v in counts.items()},
        "per_family": {k: dict(v) for k, v in sorted(fam.items())},
        "rule_level": {**_prf(rule_tp, rule_fp, rule_fn, 0),
                       "per_rule": {k: {"tp": v[0], "fp": v[1], "fn": v[2]} for k, v in sorted(per_rule.items())}},
        "parse_accuracy": {k: {"ok": v[0], "total": v[1], "accuracy": v[0] / v[1] if v[1] else None}
                           for k, v in sorted(parse_checks.items())},
        "missed": missed[:40], "false_alarms": false_alarms[:40],
    }


# ---------------------------------------------------------------------------------- real lab (strongSwan)
def evaluate_lab(lab_dir: Path, model: AnomalyModel | None) -> dict[str, Any] | None:
    """Real strongSwan traffic captured from the Docker lab; ground truth = the configs we wrote."""
    mp = lab_dir / "manifest.json"
    if not mp.exists():
        return None
    man = json.loads(mp.read_text())
    engine = RuleEngine()
    counts = {k: [0, 0, 0, 0] for k in ("combined", "rules", "ml")}
    tp = fp = fn = 0
    rows: list[dict[str, Any]] = []
    for name, m in sorted(man.items()):
        res = analyze(lab_dir / m["file"], lab_dir / m["keys"] if m.get("keys") else None, engine, model)
        est = [r for r in res.tunnels if r.tunnel.chosen is not None and r.tunnel.status == "established"]
        if not est:
            rows.append({"capture": name, "error": "no established tunnel"})
            continue
        r = est[-1]
        got = {f.rule_id for f in r.findings if f.category == "violation"}
        want = set(m["expect_rules"])
        if m["ike_version"] == 1:  # IKEv1 Quick Mode is encrypted: ESP rules unobservable
            want -= {"ESP-ENC-WEAK", "ESP-INTEG-WEAK", "ESP-NO-PFS"}
        tp += len(got & want)
        fp += len(got - want)
        fn += len(want - got)
        positive = m["label"] != "benign"
        rules_alert = r.risk.rules_component * 100 >= ALERT_RISK
        ml_alert = bool(r.anomaly and r.anomaly["is_anomalous"])
        for k, a in {"combined": rules_alert or ml_alert, "rules": rules_alert, "ml": ml_alert}.items():
            counts[k][(0 if a else 2) if positive else (1 if a else 3)] += 1
        rows.append({"capture": name, "label": m["label"], "risk": r.risk.score, "anomaly": r.anomaly["score"] if r.anomaly else None,
                     "extra_rules": sorted(got - want), "missing_rules": sorted(want - got)})
    return {"captures": len(man), "rule_level": _prf(tp, fp, fn, 0), "detection": {k: _prf(*v) for k, v in counts.items()}, "rows": rows}


# ---------------------------------------------------------------------------------- real public
def validate_public(public_dir: Path) -> dict[str, Any]:
    """Check the parser against independent oracles on real third-party captures."""
    from scapy.all import rdpcap
    from scapy.layers.isakmp import ISAKMP, ISAKMP_payload_SA
    from scapy.layers.ipsec import ESP

    man = json.loads((public_dir / "manifest.json").read_text())
    keys = load_key_table(public_dir / man["keys"])
    checks: list[dict[str, Any]] = []

    def add(kind: str, file: str, ok: bool, detail: str = "") -> None:
        checks.append({"kind": kind, "file": file, "ok": bool(ok), "detail": detail})

    for f, oracle in man["ikev2"].items():
        cap = parse_pcap(public_dir / f, keys=keys)
        got = [m.decrypted.auth_data.hex() for m in cap.ike if m.decrypted and m.decrypted.auth_data]
        add("ikev2_decrypt_auth_bytes_match_wireshark", f, oracle["auth_data"] in got)
        sc = sum(1 for p in rdpcap(str(public_dir / f)) if p.haslayer(ISAKMP))
        add("ike_message_count_matches_scapy", f, cap.stats.ike_messages == sc, f"ours={cap.stats.ike_messages} scapy={sc}")
    for f in man["ikev1"] + man["esp"]:
        cap = parse_pcap(public_dir / f)
        pk = rdpcap(str(public_dir / f))
        sc_ike = sum(1 for p in pk if p.haslayer(ISAKMP))
        add("ike_message_count_matches_scapy", f, cap.stats.ike_messages == sc_ike, f"ours={cap.stats.ike_messages} scapy={sc_ike}")
        sc_esp = sum(1 for p in pk if p.haslayer(ESP))
        add("esp_packet_count_matches_scapy", f, cap.stats.esp_packets == sc_esp, f"ours={cap.stats.esp_packets} scapy={sc_esp}")
    # IKEv1 transform attributes vs Scapy's independent ISAKMP dissector
    from scapy.layers.isakmp import ISAKMPAttributeTypes as T  # name -> (attribute id, {label: value})
    for f in man["ikev1"]:
        cap = parse_pcap(public_dir / f)
        ours = [m for m in cap.ike if m.clear.v1_proposals]
        theirs = [p for p in rdpcap(str(public_dir / f)) if p.haslayer(ISAKMP_payload_SA)]
        ok = len(ours) == len(theirs)
        for m, p in zip(ours, theirs):
            a = m.clear.v1_proposals[0].transforms[0].attrs
            sc = dict(p[ISAKMP_payload_SA].prop.trans.transforms)
            for attr_id, sname in ((1, "Encryption"), (2, "Hash"), (3, "Authentication"), (4, "GroupDesc"), (12, "LifeDuration")):
                if sname not in sc:
                    ok &= attr_id not in a
                elif sname == "LifeDuration":
                    ok &= a.get(attr_id) == sc[sname]
                else:
                    ok &= T[sname][1].get(sc[sname]) == a.get(attr_id)
        add("ikev1_transform_attributes_match_scapy", f, ok)
    by_kind: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for c in checks:
        by_kind[c["kind"]][0] += c["ok"]
        by_kind[c["kind"]][1] += 1
    return {"summary": {k: {"ok": v[0], "total": v[1]} for k, v in by_kind.items()}, "checks": checks,
            "total_ok": sum(c["ok"] for c in checks), "total": len(checks)}


# ---------------------------------------------------------------------------------- throughput
def measure_throughput(manifest_path: Path) -> dict[str, Any]:
    root = manifest_path.parent
    manifest = json.loads(manifest_path.read_text())
    engine = RuleEngine()
    pk = byt = 0
    parse_s = e2e_s = 0.0
    largest = ("", 0)
    for name, m in manifest.items():
        f = root / m["file"]
        keys = root / m["keys"] if m.get("keys") else None
        size = f.stat().st_size
        parse_pcap(f)  # warm the file cache; timings below are best-of-two
        cap = parse_pcap(f)
        pk += cap.stats.packets
        byt += size
        parse_s += min(cap.stats.parse_seconds, parse_pcap(f).stats.parse_seconds)
        best = float("inf")
        for _ in range(2):
            t0 = time.perf_counter()
            analyze(f, keys, engine)
            best = min(best, time.perf_counter() - t0)
        e2e_s += best
        if size > largest[1]:
            largest = (name, size)
    return {"captures": len(manifest), "packets": pk, "megabytes": round(byt / 1e6, 2),
            "parse_packets_per_s": round(pk / parse_s), "parse_mb_per_s": round(byt / 1e6 / parse_s, 2),
            "end_to_end_packets_per_s": round(pk / e2e_s), "largest_capture": largest[0]}


def run(manifest_path: Path, public_dir: Path, model_path: Path) -> dict[str, Any]:
    model = AnomalyModel.load(model_path)
    man = json.loads(manifest_path.read_text())
    labels: dict[str, int] = defaultdict(int)
    for m in man.values():
        for t in m["tunnels"]:
            labels[t["label"]] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "alert_threshold_risk": ALERT_RISK,
        "corpus": {"captures": len(man), "tunnels_by_label": dict(labels), "provenance": "synthetic (see README)"},
        "synthetic": evaluate_synthetic(manifest_path, model, use_keys=True),
        "synthetic_no_keys": evaluate_synthetic(manifest_path, model, use_keys=False),
        "real_public": validate_public(public_dir),
        "real_lab": evaluate_lab(manifest_path.parent / "lab", model),
        "throughput": measure_throughput(manifest_path),
        "anomaly_model": model.meta.to_dict() | {"trained_on": f"{len(model.meta.trained_on)} benign tunnels"},
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="../data/captures/manifest.json")
    ap.add_argument("--public", default="../data/public")
    ap.add_argument("--model", default=str(DEFAULT_MODEL))
    ap.add_argument("--out", default="../docs/EVAL.json")
    a = ap.parse_args()
    result = run(Path(a.manifest), Path(a.public), Path(a.model))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(result, indent=1))
    d = result["synthetic"]["detection"]
    print(json.dumps({k: {m: (round(v, 3) if isinstance(v, float) else v) for m, v in x.items()} for k, x in d.items()}, indent=1))
    print("real-public checks:", result["real_public"]["total_ok"], "/", result["real_public"]["total"])
    print("throughput:", result["throughput"])


if __name__ == "__main__":
    main()
