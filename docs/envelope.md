# Signed envelope (v1)

`/v1/policy.json` is a signed envelope, not the bare payload. Schema:
[`schema/v1/envelope.schema.json`](../schema/v1/envelope.schema.json).

```json
{
  "alg": "Ed25519",
  "kid": "example-1",
  "payload": "<base64url of the exact payload bytes>",
  "sig": "<base64url of the 64-byte Ed25519 signature>"
}
```

| Field | Description |
|---|---|
| `alg` | Always `Ed25519`. |
| `kid` | Id of the signing key. Selects the public key the client verifies with; must equal `payload.kid`. |
| `payload` | base64url (RFC 4648 section 5, **no padding**) of the exact UTF-8 bytes of the payload JSON. |
| `sig` | base64url (no padding) of the Ed25519 signature (64 bytes, 86 characters) over the **decoded payload bytes**. |

## Why the payload is a string

The signature covers exact bytes. Carrying the payload as base64url means no party ever has to
re-serialise JSON (key order, whitespace, number formatting) to verify it.

## Signing (admin tool)

1. Build the payload JSON, validate it against `policy.schema.json`, serialise to UTF-8 bytes.
2. `sig = Ed25519_sign(private_key, bytes)`.
3. Write the envelope with `payload = base64url(bytes)`, `sig = base64url(sig)`, `kid` of the key used.

## Verification (client)

1. Parse the envelope; require `alg == "Ed25519"`.
2. Look up the embedded public key for `kid`; unknown `kid` means reject.
3. base64url-decode `payload` and `sig`; verify the signature over the payload bytes. Reject on failure.
4. **Only after** verification, parse the payload; require `payload.kid == kid` and `schema_version == 1`.
5. Reject if `sequence` is lower than the last accepted; then apply the policy.

## Example

[`examples/v1/envelope.example.json`](../examples/v1/envelope.example.json) wraps the minimal payload.
Its `sig` is 64 zero bytes and its `kid` is fictional, so **it does not verify** against any key. It
only demonstrates the format. Real signed output comes from the admin CLI.
