# Branch protection for `main`

`main` is what GitHub Pages serves, so whatever lands there is published. Protect it.

## Rules

| Rule | Setting | Why |
|---|---|---|
| Restrict deletions | on | `main` must not disappear |
| Block force pushes | on | Published history and the sequence-number check rely on it |
| Require deployments to succeed | on, **no environments selected** | See the note below |
| Require a pull request before merging | on, 0 approvals | Every change is reviewable and goes through CI; single maintainer, raise it when there is a second one |
| - Dismiss stale approvals on new commits | on | |
| - Require conversation resolution | on | |
| Require status checks to pass | on, `validate` required, branch must be up to date | The `policy-ci` job: schema, signature, sequence, windows, tests |
| Require code scanning results | on, CodeQL: security alerts high or higher, alerts errors | |
| Require code quality results | on, severity errors | |
| Restrict creations/updates, linear history, signed commits, code coverage, Copilot review | off | |
| Bypass actors | none | The rules apply to admins too |

**Deployments rule:** it is included because it is enabled on the live ruleset, but no environment is
selected, so it blocks nothing. Do not select `github-pages` here: Pages deploys only *after* a push
to `main`, so requiring it as a precondition would block every merge.

The ruleset is committed at [`.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json).
It is a record and an import file; GitHub does not apply it automatically.

## Apply it (repo admin, one time)

1. Repo -> Settings -> Rules -> Rulesets -> New ruleset -> **Import a ruleset**.
2. Choose `.github/rulesets/protect-main.json` and confirm.
3. Check that the required status check shows as `validate` (it appears in the picker after the workflow has run once; the screenshot of an in-progress ruleset showed none added yet).
4. Open a test PR and confirm merging is blocked until `validate` is green.

Manual equivalent: Settings -> Rules -> New branch ruleset -> target the default branch ->
tick the rules in the table above, with `Require status checks to pass` = `validate`.

## Status

- [x] Ruleset defined and committed
- [ ] Ruleset imported and active on `coldsofttech/vethuq-policy` (needs a repo admin; tick when done)

## Notes

- If the job is ever renamed in `policy-ci.yml`, update the required check name here and in the ruleset.
- To publish in an emergency, open a PR and merge it once `validate` is green; do not disable the ruleset.
