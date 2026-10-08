# Examples (not served as policy)

Unsigned, illustrative payloads valid against `schema/v1/policy.schema.json`. They are **not** the live
policy; the live signed envelope is `/v1/policy.json`. All URLs, hashes and the key id are fictional.

| File | Shows |
|---|---|
| `minimal.payload.json` | Smallest valid payload |
| `with-notice.payload.json` | A notice with a time window and link |
| `feature-disabled.payload.json` | A feature flag disabled (kill switch) |
| `with-promotion-window.payload.json` | Downloads, add-on API range and a time-boxed promotion |
| `envelope.example.json` | Envelope wrapping the minimal payload (placeholder signature, does not verify) |
