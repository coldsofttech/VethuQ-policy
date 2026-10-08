# Branch protection for `main`

`main` is what GitHub Pages serves, so whatever lands there is published. Protect it.

## Rules

| Rule | Why |
|---|---|
| Require a pull request before merging | Every policy change is reviewable and goes through CI |
| Require status check **`validate`** to pass | The `policy-ci` workflow job: schema, signature, sequence, windows, tests |
| Block force pushes (`non_fast_forward`) | Published history, and the sequence-number check, rely on linear history |
| Block deletion | `main` must not disappear |
| Required approvals: **0** | This is a single-maintainer repo; raise it when a second maintainer exists |
| Bypass actors: none | The rules apply to admins too |

The ruleset is committed at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json).
It is a record and an import file; GitHub does not apply it automatically.

## Apply it (repo admin, one time)

1. Repo -> Settings -> Rules -> Rulesets -> New ruleset -> **Import a ruleset**.
2. Choose `.github/rulesets/protect-main.json` and confirm.
3. Check that the status check shows as `validate` (it appears in the picker only after the workflow has run once).
4. Open a test PR and confirm merging is blocked until `validate` is green.

Manual equivalent: Settings -> Rules -> New branch ruleset -> target the default branch ->
tick the rules in the table above, with `Require status checks to pass` = `validate`.

## Status

- [x] Ruleset defined and committed
- [ ] Ruleset imported and active on `coldsofttech/vethuq-policy` (needs a repo admin; tick when done)

## Notes

- If the job is ever renamed in `policy-ci.yml`, update the required check name here and in the ruleset.
- To publish in an emergency, open a PR and merge it once `validate` is green; do not disable the ruleset.
