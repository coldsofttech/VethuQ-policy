# Policy schema v1

The schema is the contract between this repo, the core client and the admin tool.

- Envelope: [`schema/v1/envelope.schema.json`](../schema/v1/envelope.schema.json) (see [envelope.md](envelope.md))
- Payload: [`schema/v1/policy.schema.json`](../schema/v1/policy.schema.json) (JSON Schema draft 2020-12)
- Examples: [`examples/v1/`](../examples/v1/)

## Compatibility rules

1. **Additive only within a major.** Within v1 we may add optional fields, new enum values for
   fields documented as extensible, and new top-level sections. We never remove, rename or
   change the meaning or type of an existing field.
2. **Unknown fields are ignored.** Clients MUST ignore fields (and `features` entries) they do not
   understand. The schema leaves `additionalProperties` open for this reason.
3. **Breaking changes go to a new major**, served from `/v2/`. `/v1/` stays available for old clients.
4. Clients treat a missing optional section as "nothing to apply".

## Payload fields

Required: `schema_version`, `sequence`, `issued_at`, `kid`, `versions`.

### Metadata

| Field | Type | Description |
|---|---|---|
| `schema_version` | integer, const `1` | Schema major. |
| `sequence` | integer >= 1 | Monotonic. Clients reject a sequence lower than the last accepted one (rollback protection). |
| `issued_at` | date-time (UTC) | When the policy was signed. |
| `kid` | string | Signing key id. Must equal the envelope `kid`; clients reject a mismatch. |

### `versions` (required)

Keys `desktop` and `pip`, each a distribution object:

| Field | Type | Description |
|---|---|---|
| `latest` | semver | Newest released version. |
| `minimum_supported` | semver | Clients below this must update. |
| `release_notes_url` | https URL, optional | Release notes for `latest`. |
| `downloads` | array, optional | Per-platform entries (normally desktop only). |

Download entry (all required): `platform` (e.g. `windows-x64`, `macos-arm64`, `linux-x64`),
`url` (https), `size` (bytes), `sha256` (lowercase hex). Clients MUST verify `sha256`.

### `compatibility` (optional)

`addon_api.min` / `addon_api.max`: inclusive semver range of the add-on API supported by `latest`.

### `notices` (optional)

Array of `{ id, message, severity, link?, starts_at?, ends_at? }`.
`severity` is `info`, `warning` or `critical`. `id` is stable so a dismissed notice stays dismissed.
A notice is shown only inside its optional time window (open-ended when a bound is omitted).
`message` is plain text, max 500 characters; clients must not render it as HTML.

### `features` (optional)

Object keyed by flag name (`^[a-z][a-z0-9_]*$`), each `{ enabled, min_client? }`.
`min_client` limits the flag to clients at or above that version. `enabled: false` is also the
remote kill switch. An absent flag means the client's built-in default applies.
Example: `"github_tier": { "enabled": false, "min_client": "1.0.0" }`.

### `limits` (optional)

Time-boxed limit adjustments and promotions. **Structure only; policies issued in the initial v1
rollout leave it empty or omit it.** Item (all required except `min_client`):
`id`, `kind` (`limit_adjustment` | `promotion`), `starts_at`, `ends_at`, `min_client?`,
`adjustments` (object of name to number/boolean/string). Applies only while now is inside
`[starts_at, ends_at]`. Which adjustment names exist is defined by the client when it implements them;
unknown names are ignored.

### `revocations` (reserved)

Licence ids to revoke. **Reserved and MUST be empty in v1** (the schema enforces `maxItems: 0`).
Clients ignore it until a later additive change defines its use.
