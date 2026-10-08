import base64
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import validate_policy as vp  # noqa: E402

KID = "test-1"


def b64(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def make_payload(**over):
    p = json.loads((ROOT / "examples/v1/minimal.payload.json").read_text())
    p["kid"] = KID
    p.update(over)
    return p


class Signer:
    """Ephemeral test key: generated per test, never written to the repo."""

    def __init__(self, keys_dir):
        self.private_key = Ed25519PrivateKey.generate()
        pub = self.private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.keys_dir = keys_dir
        keys_dir.mkdir()
        (keys_dir / f"{KID}.pub").write_text(b64(pub))

    def sign(self, payload, kid=KID, key=None):
        raw = json.dumps(payload, separators=(",", ":")).encode()
        key = key or self.private_key
        return {"alg": "Ed25519", "kid": kid, "payload": b64(raw), "sig": b64(key.sign(raw))}


class ValidatorTestCase:
    """Shared fixtures and helpers."""

    @pytest.fixture
    def signer(self, tmp_path):
        return Signer(tmp_path / "keys")

    @pytest.fixture
    def validator(self, signer):
        return vp.PolicyValidator(keys_dir=signer.keys_dir)

    @staticmethod
    def envelope_errors(validator, env, prev=None):
        return validator.validate_envelope(env, prev)[0]


class TestExamples:
    validator = vp.PolicyValidator()

    def test_example_payloads_pass(self):
        files = list((ROOT / "examples/v1").glob("*.payload.json"))
        assert files
        for f in files:
            assert self.validator.validate_payload(json.loads(f.read_text())) == [], f.name

    def test_example_envelope_matches_envelope_schema(self):
        env = json.loads((ROOT / "examples/v1/envelope.example.json").read_text())
        assert self.validator.schema_errors(env, "envelope.schema.json") == []


class TestSchema(ValidatorTestCase):
    def test_valid_envelope_passes(self, signer, validator):
        assert self.envelope_errors(validator, signer.sign(make_payload())) == []

    def test_schema_violation(self, signer, validator):
        p = make_payload()
        del p["versions"]
        assert any("versions" in e for e in self.envelope_errors(validator, signer.sign(p)))

    def test_non_empty_revocations_rejected(self, signer, validator):
        env = signer.sign(make_payload(revocations=[{"license_id": "x"}]))
        assert self.envelope_errors(validator, env)

    def test_unknown_fields_ignored(self, signer, validator):
        env = signer.sign(make_payload(future_field={"a": 1}))
        assert self.envelope_errors(validator, env) == []

    @pytest.mark.parametrize(
        "field,value",
        [
            ("sha256", "xyz"),
            ("url", "http://example.com/a.exe"),
            ("size", 0),
        ],
    )
    def test_download_format_checks(self, signer, validator, field, value):
        download = {"platform": "windows-x64", "url": "https://example.com/a.exe", "size": 10, "sha256": "a" * 64}
        download[field] = value
        p = make_payload()
        p["versions"]["desktop"]["downloads"] = [download]
        assert self.envelope_errors(validator, signer.sign(p))

    def test_minimum_supported_not_above_latest(self, signer, validator):
        p = make_payload()
        p["versions"]["desktop"]["minimum_supported"] = "2.0.0"
        errs = self.envelope_errors(validator, signer.sign(p))
        assert any("minimum_supported" in e for e in errs)


class TestSignature(ValidatorTestCase):
    def test_bad_signature(self, signer, validator):
        env = signer.sign(make_payload(), key=Ed25519PrivateKey.generate())
        assert any("signature" in e for e in self.envelope_errors(validator, env))

    def test_tampered_payload(self, signer, validator):
        env = signer.sign(make_payload())
        env["payload"] = signer.sign(make_payload(sequence=99))["payload"]
        assert any("signature" in e for e in self.envelope_errors(validator, env))

    def test_missing_signature(self, signer, validator):
        env = signer.sign(make_payload())
        del env["sig"]
        assert self.envelope_errors(validator, env)

    def test_unknown_kid(self, signer, validator):
        env = signer.sign(make_payload(kid="other"), kid="other")
        assert any("no public key" in e for e in self.envelope_errors(validator, env))

    def test_kid_mismatch(self, signer, validator):
        env = signer.sign(make_payload(kid="x-2"))
        assert any("kid" in e for e in self.envelope_errors(validator, env))


class TestSequence(ValidatorTestCase):
    def test_sequence_must_increase(self, signer, validator):
        prev = signer.sign(make_payload(sequence=5))
        assert self.envelope_errors(validator, signer.sign(make_payload(sequence=6)), prev) == []
        for seq in (5, 4):
            errs = self.envelope_errors(validator, signer.sign(make_payload(sequence=seq)), prev)
            assert any("strictly greater" in e for e in errs)

    def test_skipped_for_placeholder_previous(self, signer, validator):
        env = signer.sign(make_payload(sequence=1))
        assert self.envelope_errors(validator, env, {"_placeholder": True}) == []


class TestWindows(ValidatorTestCase):
    @pytest.mark.parametrize(
        "starts,ends",
        [
            ("2026-11-02T00:00:00Z", "2026-11-01T00:00:00Z"),  # end before start
            ("2026-11-01T00:00:00Z", "2026-11-01T00:00:00Z"),  # empty window
            ("2026-02-30T00:00:00Z", "2026-03-01T00:00:00Z"),  # impossible date
            ("2026-11-01", "2026-11-02T00:00:00Z"),  # no time / timezone
        ],
    )
    def test_invalid_notice_window(self, signer, validator, starts, ends):
        notices = [{"id": "n", "message": "m", "severity": "info", "starts_at": starts, "ends_at": ends}]
        assert self.envelope_errors(validator, signer.sign(make_payload(notices=notices)))

    def test_limit_window_ordered(self, signer, validator):
        ok = {
            "id": "p",
            "kind": "promotion",
            "starts_at": "2026-11-01T00:00:00Z",
            "ends_at": "2026-11-02T00:00:00Z",
            "adjustments": {"a": 1},
        }
        assert self.envelope_errors(validator, signer.sign(make_payload(limits=[ok]))) == []
        bad = dict(ok, ends_at="2026-10-01T00:00:00Z")
        assert self.envelope_errors(validator, signer.sign(make_payload(limits=[bad])))


class TestCli:
    def test_placeholder_accepted(self, tmp_path):
        f = tmp_path / "policy.json"
        f.write_text('{"_placeholder": true}')
        assert vp.main(["envelope", str(f), "--keys-dir", str(tmp_path)]) == 0

    def test_unsigned_non_placeholder_rejected(self, tmp_path):
        f = tmp_path / "policy.json"
        f.write_text('{"foo": 1}')
        assert vp.main(["envelope", str(f), "--keys-dir", str(tmp_path)]) == 1

    def test_repo_policy_json_passes(self):
        args = ["envelope", str(ROOT / "v1/policy.json"), "--keys-dir", str(ROOT / "keys")]
        assert vp.main(args) == 0
