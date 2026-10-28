"""Static contract and rejection boundaries of the isolated Arkhe profile."""
import copy
import hashlib
import json

import pytest

from tools.verify_arkhe_interop import FIXTURES, accepted, replay

JOBS = json.loads((FIXTURES / "arkhe-vectors.json").read_bytes())
EXPECTED = json.loads((FIXTURES / "expected.json").read_bytes())
BY_ID = {v["id"]: v for v in JOBS}


@pytest.mark.parametrize("job,expected", zip(JOBS, EXPECTED), ids=[v["id"] for v in JOBS])
def test_static_verdict(job, expected):
    assert accepted(job) is expected["accepted"]


def test_frozen_replay_and_pins():
    assert len(replay()) == 8


@pytest.mark.parametrize("changes", [
    {"path": []}, {"index": 3}, {"size": 0}, {"index": True},
    {"size": 2**64}, {"root_hex": "00" * 32},
    {"path": BY_ID["merkle-valid-0"]["path"] + ["00" * 32]},
])
def test_inclusion_rejects_invalid_bounds_and_paths(changes):
    assert not accepted(dict(BY_ID["merkle-valid-0"], **changes))


def test_unbalanced_rightmost_leaf_and_single_empty_leaf():
    a, b, c = [b"arkhe-interop-" + x for x in (b"a", b"b", b"c")]
    leaf = lambda x: hashlib.sha256(b"\x00" + x).digest()
    left = hashlib.sha256(b"\x01" + leaf(a) + leaf(b)).hexdigest()
    assert accepted(dict(BY_ID["merkle-valid-0"], leaf_hex=c.hex(), index=2, path=[left]))
    assert accepted(dict(kind="inclusion", leaf_hex="", index=0, size=1,
                         path=[], root_hex=leaf(b"").hex()))


@pytest.mark.parametrize("changes", [
    {"signature_hex": "00"}, {"key_hex": "00"}, {"message_hex": "0g"},
    {"key_hex": "AA" * 32}, {"signature_hex": "00 " * 64},
])
def test_signature_encoding_fails_closed(changes):
    assert not accepted(dict(BY_ID["signature-valid"], **changes))


@pytest.mark.parametrize("changes", [
    {"threshold": 0}, {"threshold": True}, {"message_hex": "00"},
    {"witnesses": [{"id": "unknown", "signature_hex": "00" * 64}]},
])
def test_quorum_invalid_input(changes):
    assert not accepted(dict(BY_ID["quorum-valid"], **changes))


def test_invalid_extra_witness_rejects_even_after_threshold():
    job = copy.deepcopy(BY_ID["quorum-valid"])
    job["witnesses"].append({"id": "w2", "signature_hex": "00" * 64})
    assert not accepted(job)


@pytest.mark.parametrize("job", [{}, None, [], {"kind": "unsupported"}])
def test_missing_or_unsupported_job(job):
    assert not accepted(job)
