"""IKEv1 payload decoding: the HASH payload (type 8) must be recognised (regression: V1_HASH was shadowed by a dict)."""
import pytest

from ipsec_analyzer.parser import constants as C
from ipsec_analyzer.parser.ike import parse_ike
from synth import builder as B

ISPI, RSPI = b"\x01" * 8, b"\x02" * 8


def _parse(items, exch=4):
    data = B.v1_message(ISPI, RSPI, exch, 0, 0, items)
    return parse_ike(data, frame=1, ts=0.0, src="198.51.100.1", dst="203.0.113.1", sport=500, dport=500)


def test_payload_type_and_algorithm_names_are_distinct():
    assert C.V1_HASH == 8
    assert C.V1_HASH_ALGORITHMS[2] == "SHA1"


@pytest.mark.parametrize("ptype", [C.V1_HASH, 9])  # HASH and SIG
def test_hash_or_sig_payload_sets_has_hash(ptype):
    assert _parse([(ptype, b"\xaa" * 20)]).clear.has_hash is True


def test_aggressive_mode_response_with_hash_sets_has_hash():
    msg = _parse([(C.V1_NONCE, b"\x00" * 20), (C.V1_HASH, b"\xaa" * 20)])
    assert msg.clear.has_hash is True
    assert msg.clear.nonce_len == 20


def test_message_without_hash_leaves_has_hash_unset():
    assert _parse([(C.V1_NONCE, b"\x00" * 20)]).clear.has_hash is False
