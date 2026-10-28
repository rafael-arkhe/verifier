# Arkhe primitive interoperability profile v1

Frozen 2026-10-28. These eight jobs and their expected verdicts are copied byte
for byte from the Arkhe workspace's `verification/interop/gravit-golden-v1/`.
They are a subset of its 2026-10-26 primitive exchange, which pins this upstream
verifier at `6b2ecbabd098c9a381b0b08184703905c3cb8275`.
`provenance.json` records the original file hashes and source manifest digest.
The Arkhe workspace has no Git metadata; this is a byte pin, not an Arkhe commit
or signed attestation. Preserve the manifest hash separately when exchanging it.

| ID | accepted | Meaning |
| --- | --- | --- |
| merkle-valid-0 | true | Leaf 0 in a three-leaf tree |
| merkle-wrong-leaf | false | Original proof with substituted leaf |
| signature-valid | true | Exact witness message signed with Ed25519 |
| signature-tampered | false | Message replaced with byte 00 |
| quorum-valid | true | Two keys, two configured operators, threshold 2 |
| quorum-insufficient | false | Only one submitted witness |
| quorum-dependent | false | Two keys, one configured operator |
| quorum-key-alias | false | Same key under two IDs |

## Reproduce

With this repository's Python dependencies installed (`pip install -e .`):

```sh
python tools/verify_arkhe_interop.py
python tools/verify_arkhe_interop.py --json
python -m pytest tests/test_arkhe_interop.py -q
```

The runner validates SHA-256 pins and compares ordered `{id, accepted}` results
to static `expected.json`; `reason` is explanatory. No fixture regeneration,
Gravit service, Rust install or Arkhe checkout is required. CI consumes these
frozen files; the existing golden-vector generator does not produce them.

To cross-check with Arkhe, run its
`python verification/interop/gravit-golden-v1/verify.py` in the Arkhe workspace.
That invokes `arkhe-verify-core --example gravit_interop`, using its production
`gguf::supply_chain::verify_inclusion` and ed25519-dalek `verify_strict` paths.
Compare all eight IDs and booleans. These vectors exercise ordinary Ed25519
encodings; agreement does not establish parity on every adversarial encoding.

## Reader specification

All hex fields encode raw bytes using two lowercase hex characters per byte.
Reject invalid encodings, missing fields, wrong lengths and unknown job kinds.
Unsigned integers fit u64 and cannot be booleans. IDs are labels. JSON text is
never implicitly signed. Roots, public keys and path nodes are 32 bytes;
signatures are 64 bytes.

**Inclusion:** SHA-256 `leaf_hash = H(00 || leaf_bytes)` and
`node_hash = H(01 || left_hash || right_hash)`, with single-byte prefixes.
The tree splits at the largest power of two strictly below its size. `index`
is zero-based; `size` counts leaves; siblings in `path` are bottom-up. Require
size > 0, index < size, exact path consumption and equality with `root_hex`.
The fixture tree contains UTF-8 `arkhe-interop-a`, `arkhe-interop-b`,
`arkhe-interop-c` without terminators. Its root is
`5128b63cc0fbd21844460760d5764ade0badf77535eee278c685a8807550f40d`.
For leaf 0, calculate `H(01 || H(01 || H(00 || leaf) || path[0]) || path[1])`.
The runner uses an independent recursive RFC 6962 algorithm, not Arkhe's
iterative implementation. This is a test reader, not a new Gravit log API.

**Signature:** ordinary Ed25519 without prehash or context, over decoded
`message_hex`, with `key_hex` and `signature_hex`. The reader calls the existing
`gravit_verifier.registry._verify` primitive. The positive message is UTF-8
`arkhe-interop-witness-v1`, LF, then the raw 32-byte root; no trailing LF.

**Quorum:** `trusted` is out-of-band test configuration mapping unique IDs to
keys and nonempty operator labels. `threshold` must be positive. Every submitted
witness must resolve to a configured ID and have a valid signature on the same
message. Any invalid witness, repeated key or repeated operator rejects the
whole job, even when earlier witnesses meet the threshold. Accept only when
the distinct operator count is at least the threshold. Operator independence
is assumed from configuration, not demonstrated by cryptography.

The public fixture seeds are 32 repetitions of byte 01, 02, 03 for w0, w1, w2;
operators are op0, op1, op2. The positive quorum uses w0 and w1. The dependent
case sets w1's operator to op0. The alias case assigns w0's public key and
signature to w1. These are test keys and confer no production authority.

## Boundary with Gravit decisions

This is an explicit Arkhe exchange policy, not CANON-SIG-011 or a full kernel
request. Gravit screens invalid evidence out and evaluates admissible evidence;
this quorum profile rejects the whole job on any invalid witness. Gravit also
signs a different domain (`gravit-evidence-v1`) and record fields, so these
signatures cannot be relabeled as Gravit EvidenceRecords. No bindings, decision
IDs, registry trust thresholds or upstream golden decisions are changed.

History Keeper's Merkle code and the hosted receipt API are separate components;
this test does not validate a live inclusion proof, RFC 3161 timestamp, service
key ownership or a complete Gravit decision. A third-party reader can implement
the three rules above, consume `arkhe-vectors.json` and compare with
`expected.json` without importing this runner. Record its implementation/version
and every verdict when reporting a reproduction.
