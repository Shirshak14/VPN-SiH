"""Lab scenario definitions.

Each scenario is the single source of truth for BOTH the strongSwan configuration that
produces the capture AND the ground-truth label written to data/captures/manifest.json.
The analyzer never reads this file; the evaluation harness compares its output to the manifest.

Provenance of every capture produced here is `real-lab`: real IKE/ESP bytes exchanged
between two strongSwan daemons. The *scenarios* (weak configs, downgrades) are
lab-generated attack/misconfiguration simulations, not real-world incidents.
"""
from __future__ import annotations

from dataclasses import dataclass, field

BENIGN, WEAK, DOWNGRADE = "benign", "weak-config", "downgrade"


@dataclass
class Scenario:
    name: str
    label: str
    description: str
    ike_version: int = 2
    aggressive: bool = False
    # strongSwan proposal strings (ike / esp) for each side.
    init_ike: str = "aes256-sha256-modp2048"
    resp_ike: str = ""  # empty -> same as initiator
    init_esp: str = "aes256-sha256-modp2048"
    resp_esp: str = ""
    rekey_time: str = "0s"  # 0s = no rekey scheduled
    child_rekey_time: str = "0s"
    ping_count: int = 20
    ping_interval: float = 0.2
    # "retry": after a failed first attempt, reconfigure the initiator to these proposals and retry.
    retry_ike: str = ""
    retry_esp: str = ""
    # Ground truth for evaluation (what a correct analyzer must report).
    expect_rules: list[str] = field(default_factory=list)
    expect_negotiated_ike: str = ""  # human-readable, e.g. "AES_CBC_256/HMAC_SHA2_256_128/MODP_2048"
    handshake_should_succeed: bool = True

    def resp(self, attr: str) -> str:
        return getattr(self, "resp_" + attr) or getattr(self, "init_" + attr)


def _benign(name: str, ike: str, esp: str, *, v: int = 2, **kw) -> Scenario:
    return Scenario(
        name=name,
        label=BENIGN,
        description=f"Compliant IKEv{v} tunnel: IKE {ike}, ESP {esp}",
        ike_version=v,
        init_ike=ike,
        init_esp=esp,
        **kw,
    )


SCENARIOS: list[Scenario] = [
    # ---- benign / policy-compliant baseline (IKEv2, PFS on) ----
    _benign("ok_aes256gcm_ecp384", "aes256gcm16-prfsha384-ecp384", "aes256gcm16-ecp384", rekey_time="20s", child_rekey_time="8s", ping_count=40),
    _benign("ok_aes256gcm_curve25519", "aes256gcm16-prfsha384-curve25519", "aes256gcm16-curve25519", ping_count=25),
    _benign("ok_aes256_sha384_modp3072", "aes256-sha384-modp3072", "aes256-sha384-modp3072", child_rekey_time="10s", ping_count=35),
    _benign("ok_aes256_sha256_modp2048", "aes256-sha256-modp2048", "aes256-sha256-modp2048", ping_count=30),
    _benign("ok_aes128_sha256_modp2048", "aes128-sha256-modp2048", "aes128-sha256-modp2048", ping_count=15, ping_interval=0.4),
    _benign("ok_aes128gcm_ecp256", "aes128gcm16-prfsha256-ecp256", "aes128gcm16-ecp256", ping_count=50, ping_interval=0.1),
    _benign("ok_aes256_sha512_modp4096", "aes256-sha512-modp4096", "aes256-sha512-modp4096", ping_count=20),
    _benign("ok_aes192_sha384_ecp384", "aes192-sha384-ecp384", "aes192-sha384-ecp384", rekey_time="15s", ping_count=30),
    _benign("ok_aes256_sha256_ecp256_b", "aes256-sha256-ecp256", "aes256-sha256-ecp256", ping_count=45, ping_interval=0.15),
    _benign("ok_aes256gcm_modp3072", "aes256gcm16-prfsha384-modp3072", "aes256gcm16-modp3072", child_rekey_time="9s", ping_count=30),
    _benign("ok_aes128_sha256_curve25519", "aes128-sha256-curve25519", "aes128-sha256-curve25519", ping_count=25),
    _benign("ok_aes256_sha384_ecp521", "aes256-sha384-ecp521", "aes256-sha384-ecp521", ping_count=22),
    # ---- weak-configuration scenarios (lab-generated) ----
    Scenario(
        "weak_ikev1_aggressive_psk", WEAK,
        "IKEv1 Aggressive Mode with PSK (offline-crackable PSK hash exposed in the handshake)",
        ike_version=1, aggressive=True,
        init_ike="aes128-sha1-modp1024", init_esp="aes128-sha1",
        expect_rules=["IKE-AGGR-PSK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "IKE-V1-LEGACY", "ESP-NO-PFS", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "weak_3des_sha1_modp1024", WEAK,
        "IKEv2 with 3DES, HMAC-SHA1 and MODP-1024",
        init_ike="3des-sha1-modp1024", init_esp="3des-sha1-modp1024",
        expect_rules=["IKE-ENC-WEAK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "weak_3des_sha1_modp2048", WEAK,
        "IKEv2 with 3DES + HMAC-SHA1 over an adequate DH group",
        init_ike="3des-sha1-modp2048", init_esp="3des-sha1-modp2048",
        expect_rules=["IKE-ENC-WEAK", "IKE-INTEG-WEAK", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "weak_aes128_md5_modp1024", WEAK,
        "IKEv2 with HMAC-MD5 and MODP-1024",
        init_ike="aes128-md5-modp1024", init_esp="aes128-md5-modp1024",
        expect_rules=["IKE-INTEG-WEAK", "IKE-DH-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "weak_no_pfs", WEAK,
        "IKEv2 with strong IKE SA but ESP child SA negotiated without PFS (no DH in CREATE_CHILD_SA)",
        init_ike="aes256-sha384-modp3072", init_esp="aes256-sha384", child_rekey_time="8s", ping_count=30,
        expect_rules=["ESP-NO-PFS"],
    ),
    Scenario(
        "weak_ikev1_main_3des_modp1024", WEAK,
        "IKEv1 Main Mode with PSK, 3DES/SHA1/MODP-1024",
        ike_version=1,
        init_ike="3des-sha1-modp1024", init_esp="3des-sha1-modp1024",
        expect_rules=["IKE-ENC-WEAK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "IKE-V1-LEGACY", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "weak_ikev1_main_aes_modp2048", WEAK,
        "IKEv1 Main Mode with PSK, AES-256/SHA-256/MODP-2048 (crypto OK, protocol legacy)",
        ike_version=1,
        init_ike="aes256-sha256-modp2048", init_esp="aes256-sha256-modp2048",
        expect_rules=["IKE-V1-LEGACY"],
    ),
    Scenario(
        "weak_des_md5_modp768", WEAK,
        "IKEv2 with single-DES, HMAC-MD5 and MODP-768 (worst-case legacy suite)",
        init_ike="des-md5-modp768", init_esp="des-md5-modp768",
        expect_rules=["IKE-ENC-WEAK", "IKE-INTEG-WEAK", "IKE-DH-WEAK", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    # ---- downgrade scenarios (lab-generated) ----
    Scenario(
        "downgrade_offer_strong_chosen_weak", DOWNGRADE,
        "Initiator offers strong+weak; responder (attacker/misconfig) selects the weak suite",
        init_ike="aes256-sha384-modp3072,3des-sha1-modp1024", resp_ike="3des-sha1-modp1024",
        init_esp="aes256-sha384-modp3072,3des-sha1-modp1024", resp_esp="3des-sha1-modp1024",
        expect_rules=["SA-DOWNGRADE", "IKE-ENC-WEAK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "downgrade_retry_after_reject", DOWNGRADE,
        "Strong proposal rejected (NO_PROPOSAL_CHOSEN) then initiator retries with weaker suite",
        init_ike="aes256-sha384-modp3072", resp_ike="3des-sha1-modp1024",
        init_esp="aes256-sha384-modp3072", resp_esp="3des-sha1-modp1024",
        retry_ike="3des-sha1-modp1024", retry_esp="3des-sha1-modp1024",
        expect_rules=["SA-DOWNGRADE", "IKE-ENC-WEAK", "IKE-DH-WEAK", "IKE-INTEG-WEAK", "ESP-ENC-WEAK", "ESP-INTEG-WEAK"],
    ),
    Scenario(
        "downgrade_dh_only", DOWNGRADE,
        "Initiator offers MODP-3072 first and MODP-1024 second; responder pins MODP-1024",
        init_ike="aes256-sha256-modp3072,aes256-sha256-modp1024", resp_ike="aes256-sha256-modp1024",
        init_esp="aes256-sha256-modp3072,aes256-sha256-modp1024", resp_esp="aes256-sha256-modp1024",
        expect_rules=["SA-DOWNGRADE", "IKE-DH-WEAK"],
    ),
]
