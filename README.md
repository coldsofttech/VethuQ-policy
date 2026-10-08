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
remain as fallbacks. How the list is used and how to move hosts without a client release:
[docs/hosting-and-mirrors.md](docs/hosting-and-mirrors.md). Mirrors may be cached (jsDelivr in particular), so clients must
rely on the signature and the policy's own validity fields, never on fetch freshness.

## Publishing flow

1. Draft the policy in the **private entitlements repo**.
2. Sign it with the **admin CLI** (the private key never leaves the admin environment).
3. Commit only the **signed output** to `v1/policy.json` here, via pull request.
4. Pages redeploys from `main`; verify the primary URL returns JSON with
   `Content-Type: application/json`.

This repository only ever receives signed output. Unsigned drafts are not authored here.

## Protection and hosting terms

- `main` protection (PR + required `validate` check, no force-push or deletion):
  [docs/branch-protection.md](docs/branch-protection.md)
- GitHub Pages acceptable-use review: [docs/acceptable-use.md](docs/acceptable-use.md)

## CI checks

The `policy-ci` workflow runs on every push and PR, with no secrets (public keys only). It runs the
unit tests, validates the example payloads, and validates `v1/policy.json`:

- envelope and payload schema (`schema/v1/`)
- Ed25519 signature against the public key `keys/<kid>.pub` (see [keys/README.md](keys/README.md))
- `sequence` strictly greater than the previous commit's `v1/policy.json` (only when the file changed)
- notice and limit windows (`starts_at` before `ends_at`, real dates), URL, sha256 and version formats

Run locally: `pip install -r requirements-ci.txt && python -m pytest tests &&
python scripts/validate_policy.py envelope v1/policy.json`.

### Pre-commit

`pip install pre-commit && pre-commit install` runs on each commit: whitespace/EOF/YAML/JSON checks,
private-key detection, `ruff` lint and format, the policy checks (`scripts/check_policy.sh`) and the tests.
Run everything with `pre-commit run --all-files`.

While `v1/policy.json` is the documented unsigned placeholder (`"_placeholder": true`), the check
passes with a warning. Once the first signed policy is committed, the placeholder is no longer accepted
there as soon as a signed file replaces it, and it must verify like any other.

## Never commit

- Private keys or key material of any kind
- Licence issue logs
- Customer data (names, emails, licence identifiers tied to people)
- Unannounced promotions or anything not yet public
- Unsigned or hand-edited policy files

Everything here is world-readable and permanently in git history.

## License

See [LICENSE](LICENSE).
