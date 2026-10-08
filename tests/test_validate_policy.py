import base64
import copy
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import validate_policy as vp  # noqa: E402


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


@pytest.fixture
def signer(tmp_path):
    """Ephemeral test key: generated per test, never written to the repo."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = tmp_path / "keys"
    keys.mkdir()
    (keys / "test-1.pub").write_text(b64(pub))

    def sign(payload, kid="test-1", key=priv):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return {"alg": "Ed25519", "kid": kid, "payload": b64(raw), "sig": b64(key.sign(raw))}

    return sign, keys


def payload(**over):
    p = json.loads((ROOT / "examples/v1/minimal.payload.json").read_text())
    p["kid"] = "test-1"
    p.update(over)
    return p


def errs(env, keys, prev=None):
    return vp.check_envelope(env, keys, prev)[0]


def test_valid_envelope_passes(signer):
    sign, keys = signer
    assert errs(sign(payload()), keys) == []


def test_examples_pass():
    for f in (ROOT / "examples/v1").glob("*.payload.json"):
        assert vp.check_payload(json.loads(f.read_text())) == [], f.name


def test_example_envelope_matches_envelope_schema():
    env = json.loads((ROOT / "examples/v1/envelope.example.json").read_text())
    assert vp.schema_errors(env, "envelope.schema.json") == []


def test_schema_violation(signer):
    sign, keys = signer
    p = payload()
    del p["versions"]
    assert any("versions" in e for e in errs(sign(p), keys))


def test_non_empty_revocations_rejected(signer):
    sign, keys = signer
    assert errs(sign(payload(revocations=[{"license_id": "x"}])), keys)


def test_bad_signature(signer):
    sign, keys = signer
    env = sign(payload(), key=Ed25519PrivateKey.generate())
    assert any("signature" in e for e in errs(env, keys))


def test_tampered_payload(signer):
    sign, keys = signer
    env = sign(payload())
    env["payload"] = sign(payload(sequence=99))["payload"]
    assert any("signature" in e for e in errs(env, keys))


def test_missing_signature(signer):
    sign, keys = signer
    env = sign(payload())
    del env["sig"]
    assert errs(env, keys)


def test_unknown_kid(signer):
    sign, keys = signer
    assert any("no public key" in e for e in errs(sign(payload(kid="other"), kid="other"), keys))


def test_kid_mismatch(signer):
    sign, keys = signer
    assert any("kid" in e for e in errs(sign(payload(kid="x-2")), keys))


def test_sequence_must_increase(signer):
    sign, keys = signer
    prev = sign(payload(sequence=5))
    assert errs(sign(payload(sequence=6)), keys, prev) == []
    assert any("strictly greater" in e for e in errs(sign(payload(sequence=5)), keys, prev))
    assert any("strictly greater" in e for e in errs(sign(payload(sequence=4)), keys, prev))


def test_sequence_skipped_for_placeholder_previous(signer):
    sign, keys = signer
    assert errs(sign(payload(sequence=1)), keys, {"_placeholder": True}) == []


@pytest.mark.parametrize("starts,ends", [
    ("2026-11-02T00:00:00Z", "2026-11-01T00:00:00Z"),  # end before start
    ("2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"),  # empty window
    ("2026-02-30T00:00:00Z", "2026-03-01T00:00:00Z"),  # impossible date
    ("2026-11-01", "2026-11-02T00:00:00Z"),            # no time / timezone
])
def test_invalid_notice_window(signer, starts, ends):
    sign, keys = signer
    n = [{"id": "n", "message": "m", "severity": "info", "starts_at": starts, "ends_at": ends}]
    assert errs(sign(payload(notices=n)), keys)


def test_limit_window_required_and_ordered(signer):
    sign, keys = signer
    ok = {"id": "p", "kind": "promotion", "starts_at": "2026-11-01T00:00:00Z",
          "ends_at": "2026-11-02T00:00:00Z", "adjustments": {"a": 1}}
    assert errs(sign(payload(limits=[ok])), keys) == []
    bad = dict(ok, ends_at="2026-10-01T00:00:00Z")
    assert errs(sign(payload(limits=[bad])), keys)


def test_download_format_checks(signer):
    sign, keys = signer
    p = payload()
    good = {"platform": "windows-x64", "url": "https://example.com/a.exe", "size": 10, "sha256": "a" * 64}
    for bad in (dict(good, sha256="xyz"), dict(good, url="http://example.com/a.exe"), dict(good, size=0)):
        q = copy.deepcopy(p)
        q["versions"]["desktop"]["downloads"] = [bad]
        assert errs(sign(q), keys), bad


def test_minimum_supported_not_above_latest(signer):
    sign, keys = signer
    p = payload()
    p["versions"]["desktop"]["minimum_supported"] = "2.0.0"
    assert any("minimum_supported" in e for e in errs(sign(p), keys))


def test_unknown_fields_ignored(signer):
    sign, keys = signer
    assert errs(sign(payload(future_field={"a": 1})), keys) == []


def test_placeholder_accepted_via_cli(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text('{"_placeholder": true}')
    assert vp.main(["envelope", str(f), "--keys-dir", str(tmp_path)]) == 0


def test_unsigned_non_placeholder_rejected_via_cli(tmp_path):
    f = tmp_path / "policy.json"
    f.write_text('{"foo": 1}')
    assert vp.main(["envelope", str(f), "--keys-dir", str(tmp_path)]) == 1


def test_repo_policy_json_passes():
    assert vp.main(["envelope", str(ROOT / "v1/policy.json"), "--keys-dir", str(ROOT / "keys")]) == 0
