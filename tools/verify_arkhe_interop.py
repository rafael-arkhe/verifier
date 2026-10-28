"""Frozen Arkhe primitive profile; not a Gravit kernel decision adapter."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from gravit_verifier.registry import _verify

FIXTURES = ROOT / "tests/interop/arkhe-v1"


def raw(value, length=None):
    if not isinstance(value, str) or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("expected lowercase hex")
    result = bytes.fromhex(value)
    if len(value) != len(result) * 2 or (length is not None and len(result) != length):
        raise ValueError("incorrect byte length")
    return result


def uint(value):
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError("expected u64")
    return value


def text(value):
    if not isinstance(value, str) or not value:
        raise ValueError("expected nonempty text")
    return value


def signature(key, message, sig):
    # Reuse Gravit's exact Ed25519 verification path, with decoded profile bytes.
    return _verify(raw(key, 32), raw(sig, 64), raw(message))


def inclusion(v):
    size, index = uint(v["size"]), uint(v["index"])
    if size == 0 or index >= size or not isinstance(v["path"], list) or len(v["path"]) > 64:
        return False
    siblings = iter(raw(s, 32) for s in v["path"])
    leaf, root = raw(v["leaf_hex"]), raw(v["root_hex"], 32)

    def ascend(i, n):
        if n == 1:
            return hashlib.sha256(b"\x00" + leaf).digest()
        split = 1 << ((n - 1).bit_length() - 1)
        if i < split:
            child = ascend(i, split)
            left, right = child, next(siblings)
        else:
            child = ascend(i - split, n - split)
            left, right = next(siblings), child
        return hashlib.sha256(b"\x01" + left + right).digest()

    result = ascend(index, size)
    return next(siblings, None) is None and result == root


def quorum(v):
    threshold = uint(v["threshold"])
    raw(v["message_hex"])
    if threshold == 0 or not isinstance(v["trusted"], list) or not isinstance(v["witnesses"], list):
        return False
    trusted = {}
    for entry in v["trusted"]:
        identity = text(entry["id"])
        raw(entry["key_hex"], 32)
        text(entry["operator"])
        if identity in trusted:
            return False
        trusted[identity] = entry
    keys, operators = set(), set()
    for witness in v["witnesses"]:
        entry = trusted.get(text(witness["id"]))
        if entry is None:
            return False
        key, operator = entry["key_hex"], entry["operator"]
        if key in keys or operator in operators:
            return False
        if not signature(key, v["message_hex"], witness["signature_hex"]):
            return False
        keys.add(key)
        operators.add(operator)
    return len(operators) >= threshold


def accepted(v):
    """Malformed or unsupported primitive jobs fail closed."""
    try:
        if v["kind"] == "inclusion":
            return inclusion(v)
        if v["kind"] == "signature":
            return signature(v["key_hex"], v["message_hex"], v["signature_hex"])
        if v["kind"] == "quorum":
            return quorum(v)
    except (KeyError, TypeError, ValueError, StopIteration):
        return False
    return False


def replay():
    for item in json.loads((FIXTURES / "manifest.json").read_bytes()):
        actual = hashlib.sha256((ROOT / item["path"]).read_bytes()).hexdigest()
        if actual != item["sha256"]:
            raise ValueError(f"Hash mismatch: {item['path']}")
    jobs = json.loads((FIXTURES / "arkhe-vectors.json").read_bytes())
    expected = json.loads((FIXTURES / "expected.json").read_bytes())
    ids = [v["id"] for v in jobs]
    if len(ids) != 8 or len(set(ids)) != len(ids) or ids != [v["id"] for v in expected]:
        raise ValueError("expected eight unique cases in matching order")
    actual = [{"id": v["id"], "accepted": accepted(v)} for v in jobs]
    if actual != [{"id": v["id"], "accepted": v["accepted"]} for v in expected]:
        raise ValueError(f"Verdict mismatch: {actual}")
    return actual


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit verified ordered verdicts")
    args = parser.parse_args()
    try:
        results = replay()
    except ValueError as error:
        raise SystemExit(str(error))
    print(json.dumps(results, indent=2) if args.json else f"PASS: {len(results)}/8 Arkhe primitive cases; SHA-256 pins match")
