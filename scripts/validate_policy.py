#!/usr/bin/env python3
"""Validate VethuQ policy files. Needs only public keys; no secrets.

  validate_policy.py envelope FILE --keys-dir keys [--previous PREV_FILE]
  validate_policy.py payload FILE

`envelope` checks: envelope schema, Ed25519 signature against keys/<kid>.pub, payload schema,
semantic rules (windows, versions, kid match) and, if --previous is given and the file
changed, that sequence is strictly greater than the previous one.
`payload` checks only the payload schema and semantic rules (used for unsigned examples).

Exit code 0 = valid, 1 = invalid. A file that is exactly the documented unsigned
placeholder (`"_placeholder": true`) is accepted with a warning until the first signed policy lands.
"""
import argparse
import base64
import binascii
import json
import re
import sys
from datetime import datetime
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_DIR = ROOT / "schema" / "v1"
KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SEMVER_RE = re.compile(r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")


class PolicyError(Exception):
    pass


def b64url_decode(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as e:
        raise PolicyError(f"invalid base64url: {e}")


def load_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise PolicyError(f"cannot read {path}: {e}")


def schema_errors(instance, schema_name):
    schema = json.loads((SCHEMA_DIR / schema_name).read_text(encoding="utf-8"))
    v = Draft202012Validator(schema)
    return [
        f"schema: {'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in sorted(v.iter_errors(instance), key=lambda e: list(map(str, e.absolute_path)))
    ]


def parse_time(value, where):
    """Strict RFC 3339 UTC-or-offset parse; rejects impossible dates like Feb 30."""
    if not isinstance(value, str) or not re.search(r"(Z|[+-]\d{2}:\d{2})$", value):
        raise PolicyError(f"{where}: timestamp must be RFC 3339 with a timezone: {value!r}")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise PolicyError(f"{where}: impossible or malformed date: {value!r}")


def semver_tuple(s):
    m = SEMVER_RE.match(s)
    return tuple(int(x) for x in m.groups())


def semantic_errors(p):
    errs = []

    def check(fn):
        try:
            fn()
        except PolicyError as e:
            errs.append(str(e))

    check(lambda: parse_time(p.get("issued_at"), "issued_at"))

    def window(obj, where, required):
        s = obj.get("starts_at")
        e = obj.get("ends_at")
        st = parse_time(s, f"{where}.starts_at") if s is not None else None
        en = parse_time(e, f"{where}.ends_at") if e is not None else None
        if required and (st is None or en is None):
            raise PolicyError(f"{where}: starts_at and ends_at are required")
        if st and en and not st < en:
            raise PolicyError(f"{where}: starts_at must be before ends_at ({s} >= {e})")

    for i, n in enumerate(p.get("notices", []) or []):
        check(lambda n=n, i=i: window(n, f"notices[{i}]", False))
    for i, l in enumerate(p.get("limits", []) or []):
        check(lambda l=l, i=i: window(l, f"limits[{i}]", True))

    for dist, d in (p.get("versions") or {}).items():
        try:
            if semver_tuple(d["minimum_supported"]) > semver_tuple(d["latest"]):
                errs.append(f"versions.{dist}: minimum_supported is greater than latest")
        except (KeyError, AttributeError, TypeError):
            pass  # reported by the schema check

    addon = (p.get("compatibility") or {}).get("addon_api")
    if addon:
        try:
            if semver_tuple(addon["min"]) > semver_tuple(addon["max"]):
                errs.append("compatibility.addon_api: min is greater than max")
        except (KeyError, AttributeError, TypeError):
            pass
    return errs


def check_payload(p):
    errs = schema_errors(p, "policy.schema.json")
    if not errs:
        errs += semantic_errors(p)
    return errs


def is_placeholder(doc):
    return isinstance(doc, dict) and doc.get("_placeholder") is True and "sig" not in doc


def load_key(keys_dir, kid):
    if not KID_RE.match(kid):
        raise PolicyError(f"invalid kid {kid!r}")
    path = Path(keys_dir) / f"{kid}.pub"
    if not path.is_file():
        raise PolicyError(f"no public key for kid {kid!r} (expected {path})")
    raw = b64url_decode(path.read_text(encoding="utf-8").strip())
    if len(raw) != 32:
        raise PolicyError(f"{path}: Ed25519 public key must be 32 bytes, got {len(raw)}")
    return Ed25519PublicKey.from_public_bytes(raw)


def check_envelope(env, keys_dir, previous=None):
    """Return (errors, payload_or_None)."""
    errs = schema_errors(env, "envelope.schema.json")
    if errs:
        return errs, None
    try:
        key = load_key(keys_dir, env["kid"])
        payload_bytes = b64url_decode(env["payload"])
        sig = b64url_decode(env["sig"])
        if len(sig) != 64:
            return [f"signature must be 64 bytes, got {len(sig)}"], None
        key.verify(sig, payload_bytes)
    except InvalidSignature:
        return ["signature does not verify against the published key"], None
    except PolicyError as e:
        return [str(e)], None
    # Only parse the payload after the signature verified.
    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except ValueError as e:
        return [f"payload is not valid UTF-8 JSON: {e}"], None
    errs = check_payload(payload)
    if not errs and payload.get("kid") != env["kid"]:
        errs.append(f"payload.kid {payload.get('kid')!r} != envelope kid {env['kid']!r}")
    if not errs and previous is not None:
        errs += check_sequence(payload, previous)
    return errs, payload


def check_sequence(payload, previous_doc):
    """previous_doc is the previous commit's policy.json (parsed). Skipped if it is a placeholder."""
    if is_placeholder(previous_doc):
        return []
    try:
        prev_bytes = b64url_decode(previous_doc["payload"])
        prev_seq = json.loads(prev_bytes.decode("utf-8"))["sequence"]
    except (KeyError, TypeError, ValueError, PolicyError):
        return []  # previous file unreadable: nothing to compare against
    if not payload["sequence"] > prev_seq:
        return [f"sequence {payload['sequence']} must be strictly greater than previous {prev_seq}"]
    return []


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="mode", required=True)
    e = sub.add_parser("envelope")
    e.add_argument("file")
    e.add_argument("--keys-dir", default=str(ROOT / "keys"))
    e.add_argument("--previous", help="previous commit's policy.json; if given and different, sequence must increase")
    pl = sub.add_parser("payload")
    pl.add_argument("file")
    a = ap.parse_args(argv)

    try:
        doc = load_json(a.file)
        if a.mode == "payload":
            errs = check_payload(doc)
        elif is_placeholder(doc):
            print(f"WARNING {a.file}: unsigned placeholder accepted; replace with signed output", file=sys.stderr)
            return 0
        else:
            prev = None
            if a.previous and Path(a.previous).is_file():
                prev = load_json(a.previous)
                if prev == doc:
                    prev = None  # unchanged file: no sequence bump required
            errs, _ = check_envelope(doc, a.keys_dir, prev)
    except PolicyError as ex:
        errs = [str(ex)]
    if errs:
        for m in errs:
            print(f"ERROR {a.file}: {m}", file=sys.stderr)
        return 1
    print(f"OK {a.file}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
