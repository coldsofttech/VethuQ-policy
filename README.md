# VethuQ-policy

Public, static home of the signed **`policy.json`** that VethuQ clients fetch to learn:

- latest and minimum supported versions
- notices
- feature flags
- (later) time-boxed limit adjustments and revocations

This lets us change behaviour without every user reinstalling. Hosting is static
(GitHub Pages, served directly from `main`, no build step), so this repository is
public and contains **only signed, non-secret data**.

## Layout

```
.nojekyll        # disables Jekyll so files are served as-is
v1/
  index.html     # placeholder so /v1/ resolves
  policy.json    # signed envelope for v1 clients (currently an unsigned placeholder)
schema/v1/       # JSON Schemas: envelope + payload
docs/            # field documentation and envelope format
examples/v1/     # illustrative unsigned payloads (not live policy)
```

See [docs/schema-v1.md](docs/schema-v1.md) for the fields and compatibility rules and
[docs/envelope.md](docs/envelope.md) for the signed envelope format.

`/v1/` is a stable contract: it stays alive for old clients even if a `/v2/`
appears later. Never repurpose or remove a published version path.

## URLs

The client embeds this ordered list and tries each in turn:

| # | Role | URL |
|---|------|-----|
| 1 | Primary (GitHub Pages) | `https://coldsofttech.github.io/vethuq-policy/v1/policy.json` |
| 2 | Mirror (jsDelivr) | `https://cdn.jsdelivr.net/gh/coldsofttech/vethuq-policy@main/v1/policy.json` |
| 3 | Mirror (raw) | `https://raw.githubusercontent.com/coldsofttech/vethuq-policy/main/v1/policy.json` |

A custom domain is optional; if added, it goes first in the list and the URLs above
remain as fallbacks. Mirrors may be cached (jsDelivr in particular), so clients must
rely on the signature and the policy's own validity fields, never on fetch freshness.

## Publishing flow

1. Draft the policy in the **private entitlements repo**.
2. Sign it with the **admin CLI** (the private key never leaves the admin environment).
3. Commit only the **signed output** to `v1/policy.json` here, via pull request.
4. Pages redeploys from `main`; verify the primary URL returns JSON with
   `Content-Type: application/json`.

This repository only ever receives signed output. Unsigned drafts are not authored here.

## Never commit

- Private keys or key material of any kind
- Licence issue logs
- Customer data (names, emails, licence identifiers tied to people)
- Unannounced promotions or anything not yet public
- Unsigned or hand-edited policy files

Everything here is world-readable and permanently in git history.

## License

See [LICENSE](LICENSE).
