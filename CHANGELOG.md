# Changelog

All notable changes to this repository are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Policy files are versioned by their
schema major (`/v1/`) and their `sequence` number, not by release tags.

## [Unreleased]

### Added
- Policy schema v1 `components` (additive, optional): `latest` / `minimum_supported` / `release_notes_url` /
  `distributions` / `premium` per separately released component, keyed by Python distribution name (`vethuq-core`,
  `vethuq-cli`, `vethuq-ui`, `vethuq-addon-<name>`), so releasing one component does not change the app-level
  `versions`. Validator check (`minimum_supported` not above `latest`), example `with-components.payload.json`,
  tests and docs (`docs/schema-v1.md`). Client side: coldsofttech/VethuQ-support#277.
- Update check (#97): `features.<name>.message` (additive, optional) so a feature held back for an older client
  can carry its own explanation; documented the client rules for `latest` / `minimum_supported` (policy is the only
  source, pre-release form, local features never blocked); example `with-update.payload.json`.
- Rollback protection rules (`docs/envelope.md`): the client records the highest sequence per signing key
  id and derives the floor from keys that are still trusted and not revoked; standby keys use their own
  counter. A forged high sequence from a compromised key can no longer block legitimate policies (#266).
- Policy schema v1 `revoked_key_ids` (additive): in-band revocation of signing key ids, honoured only from a
  policy-standby signature, immediate and permanent; envelope verification steps updated
  (`docs/schema-v1.md`, `docs/envelope.md`).
- Policy schema v1 credits sections (additive): `rate_card` (with `model_multiplier`), `wallets` (GitHub
  `daily_private` / `daily_public`, starter, add-on sub-wallets), `promotions`, `caps`, `grace_percent`,
  `grace_mode`, `metrics`, `ocr.profiles`, the `effective_from` rule (next UTC day boundary) and optional
  `applies_to` client-version scoping; validator checks and examples (`docs/schema-v1.md`).
- Hosting and mirror procedure: ordered client URL list, how to move hosts without a client release
  (`docs/hosting-and-mirrors.md`).
- Branch protection ruleset for `main` (`.github/rulesets/protect-main.json`) and its documentation
  (`docs/branch-protection.md`).
- CI workflow `policy-ci`: schema, Ed25519 signature, sequence and time-window checks, with a
  class-based validator (`scripts/validate_policy.py`) and tests, no secrets required.
- Pre-commit configuration (hygiene hooks, ruff, policy checks, tests), `pyproject.toml`, Python `.gitignore`.
- Policy schema v1: payload and envelope JSON Schemas, field documentation, envelope format and
  example policies (`schema/v1/`, `docs/`, `examples/v1/`).
- Repository README, `.nojekyll`, `/v1/` layout and an unsigned `v1/policy.json` placeholder, served
  by GitHub Pages from `main`.

### Notes
- `v1/policy.json` is still the unsigned placeholder; the first signed policy and its public key
  (`keys/<kid>.pub`) arrive with the admin tooling.
