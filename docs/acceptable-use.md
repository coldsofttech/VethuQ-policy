# GitHub Pages acceptable use

**Question:** is serving a small signed config file (`policy.json`, a few KB, fetched by an app) from
GitHub Pages within GitHub's terms?

## Assessment

- The content is a small, static, public, non-secret file with no transactions, accounts or user data.
- It is not a SaaS or commercial-transaction site, which is the kind of use GitHub's Pages terms
  restrict. It is app configuration, comparable to a version-check file.
- Expected traffic: one small request per client per check interval, cached by CDNs. Well below
  typical Pages bandwidth limits unless the user base becomes very large.

## Status: **needs maintainer confirmation**

The terms and limits could not be re-read from the environment this was written in (docs.github.com
was unreachable). Before relying on this, the maintainer should read the current
[GitHub Pages limits](https://docs.github.com/en/pages/getting-started-with-github-pages/github-pages-limits)
and the Pages section of
[GitHub Terms for Additional Products and Features](https://docs.github.com/en/site-policy/github-terms/github-terms-for-additional-products-and-features),
then record the outcome below.

| Date | Reviewer | Outcome |
|---|---|---|
| _pending_ | _pending_ | _pending_ |

## Escape hatch

If the use is ever judged out of bounds or traffic grows past Pages limits, move hosting using the URL
list in [hosting-and-mirrors.md](hosting-and-mirrors.md). Because trust comes from the signature, no
client release is needed when a custom domain is URL #1.
