"""Drive the strongSwan lab and record real IKE/ESP captures.

    python lab/generate.py                 # all scenarios
    python lab/generate.py ok_aes256_sha256_modp2048 weak_no_pfs

For each scenario: two containers (initiator, responder) on an isolated bridge network,
tcpdump on the initiator's eth0, IKE negotiation, ESP traffic (ping through the tunnel),
optional rekeys, then teardown. Output: data/captures/<name>.pcap + manifest.json.
"""
from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from scenarios import SCENARIOS, Scenario  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "captures"
IMAGE = "ipsec-lab:latest"
NET = "ipsec-labnet"
SUBNET = "10.99.0"
INIT_IP, RESP_IP = f"{SUBNET}.2", f"{SUBNET}.3"
PSK = "lab-only-shared-secret-not-a-real-credential"


def sh(*args: str, check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    r = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{' '.join(args)}\n{r.stdout}\n{r.stderr}")
    return r


def swanctl_conf(sc: Scenario, role: str, ike: str, esp: str) -> str:
    init = role == "init"
    local, remote = (INIT_IP, RESP_IP) if init else (RESP_IP, INIT_IP)
    lid, rid = ("init", "resp") if init else ("resp", "init")
    lts, rts = ("10.1.0.0/24", "10.2.0.0/24") if init else ("10.2.0.0/24", "10.1.0.0/24")
    rekey = f"rekey_time = {sc.rekey_time}" if sc.rekey_time != "0s" else ""
    crekey = f"rekey_time = {sc.child_rekey_time}" if sc.child_rekey_time != "0s" else "rekey_time = 0s"
    aggr = "aggressive = yes" if sc.aggressive else ""
    return textwrap.dedent(f"""\
        connections {{
          net {{
            version = {sc.ike_version}
            local_addrs = {local}
            remote_addrs = {remote}
            proposals = {ike}
            {aggr}
            {rekey}
            local {{ auth = psk
                     id = {lid} }}
            remote {{ auth = psk
                      id = {rid} }}
            children {{
              net {{
                local_ts = {lts}
                remote_ts = {rts}
                esp_proposals = {esp}
                {crekey}
                start_action = none
                mode = tunnel
              }}
            }}
          }}
        }}
        secrets {{
          ike-lab {{ id-a = init
                     id-b = resp
                     secret = "{PSK}" }}
        }}
        """)


def start_charon(c: str, conf: str, tmp: Path) -> None:
    f = tmp / f"{c}.conf"
    f.write_text(conf, newline="\n")
    sh("docker", "cp", str(f), f"{c}:/etc/swanctl/swanctl.conf")
    sh("docker", "exec", "-d", c, "sh", "-c", "/usr/lib/ipsec/charon > /var/log/charon.log 2>&1")
    for _ in range(40):
        if sh("docker", "exec", c, "swanctl", "--stats", check=False).returncode == 0:
            break
        time.sleep(0.25)
    else:
        raise RuntimeError(f"charon did not come up in {c}: " + sh("docker", "exec", c, "cat", "/var/log/charon.log", check=False).stdout)
    sh("docker", "exec", c, "swanctl", "--load-all")


def stop_charon(c: str) -> None:
    sh("docker", "exec", c, "pkill", "-TERM", "charon", check=False)
    time.sleep(0.5)


def run(sc: Scenario, tmp: Path) -> dict:
    ini, rsp = f"lab-init-{sc.name}"[:60].replace("_", "-"), f"lab-resp-{sc.name}"[:60].replace("_", "-")
    for c in (ini, rsp):
        sh("docker", "rm", "-f", c, check=False)
    for c, ip in ((ini, INIT_IP), (rsp, RESP_IP)):
        sh("docker", "run", "-d", "--name", c, "--network", NET, "--ip", ip,
           "--cap-add", "NET_ADMIN", "--cap-add", "NET_RAW", "--privileged", IMAGE)
    try:
        # Loopback aliases give each side a local traffic-selector address to ping.
        sh("docker", "exec", ini, "ip", "addr", "add", "10.1.0.1/32", "dev", "lo")
        sh("docker", "exec", rsp, "ip", "addr", "add", "10.2.0.1/32", "dev", "lo")
        start_charon(rsp, swanctl_conf(sc, "resp", sc.resp("ike"), sc.resp("esp")), tmp)
        start_charon(ini, swanctl_conf(sc, "init", sc.init_ike, sc.init_esp), tmp)

        sh("docker", "exec", "-d", ini, "sh", "-c",
           f"tcpdump -i eth0 -U -w /cap.pcap 'esp or ah or udp port 500 or udp port 4500' 2>/dev/null")
        time.sleep(1.0)

        ok = sh("docker", "exec", ini, "swanctl", "--initiate", "--child", "net", check=False, timeout=60).returncode == 0
        if not ok and sc.retry_ike:
            time.sleep(1.5)
            stop_charon(ini)
            start_charon(ini, swanctl_conf(sc, "init", sc.retry_ike, sc.retry_esp), tmp)
            ok = sh("docker", "exec", ini, "swanctl", "--initiate", "--child", "net", check=False, timeout=60).returncode == 0

        if ok and sc.ping_count:
            sh("docker", "exec", ini, "ping", "-I", "10.1.0.1", "-c", str(sc.ping_count),
               "-i", str(sc.ping_interval), "-s", "120", "-W", "1", "10.2.0.1", check=False, timeout=120)
            # Keep the tunnel up long enough for scheduled rekeys.
            need = max(_secs(sc.rekey_time), _secs(sc.child_rekey_time))
            if need:
                time.sleep(need * 1.6)
                sh("docker", "exec", ini, "ping", "-I", "10.1.0.1", "-c", "10", "-i", "0.2", "-W", "1", "10.2.0.1", check=False, timeout=60)
        if ok:
            sh("docker", "exec", ini, "swanctl", "--terminate", "--ike", "net", check=False)
        time.sleep(1.0)
        sh("docker", "exec", ini, "pkill", "-INT", "tcpdump", check=False)
        time.sleep(0.8)
        OUT.mkdir(parents=True, exist_ok=True)
        sh("docker", "cp", f"{ini}:/cap.pcap", str(OUT / f"{sc.name}.pcap"))
        log = sh("docker", "exec", ini, "cat", "/var/log/charon.log", check=False).stdout
        (tmp / f"{sc.name}.charon.log").write_text(log)
        return {"handshake_ok": ok}
    finally:
        for c in (ini, rsp):
            sh("docker", "rm", "-f", c, check=False)


def _secs(s: str) -> int:
    return int(s[:-1]) if s.endswith("s") else 0


def main() -> None:
    wanted = set(sys.argv[1:])
    todo = [s for s in SCENARIOS if not wanted or s.name in wanted]
    if sh("docker", "image", "inspect", IMAGE, check=False).returncode != 0:
        sh("docker", "build", "-t", IMAGE, str(Path(__file__).parent), timeout=900)
    if sh("docker", "network", "inspect", NET, check=False).returncode != 0:
        sh("docker", "network", "create", "--subnet", f"{SUBNET}.0/24", NET)

    manifest_path = OUT / "manifest.json"
    manifest = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    tmp = ROOT / "data" / "_lab_tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    for sc in todo:
        print(f"[lab] {sc.name} ...", flush=True)
        res = run(sc, tmp)
        manifest[sc.name] = {
            "file": f"{sc.name}.pcap",
            "provenance": "real-lab",
            "label": sc.label,
            "description": sc.description,
            "ike_version": sc.ike_version,
            "aggressive": sc.aggressive,
            "offered_ike": sc.init_ike,
            "responder_ike": sc.resp("ike"),
            "retry_ike": sc.retry_ike,
            "offered_esp": sc.init_esp,
            "expect_rules": sc.expect_rules,
            "handshake_ok": res["handshake_ok"],
        }
        print(f"[lab]   handshake_ok={res['handshake_ok']}", flush=True)
        manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
