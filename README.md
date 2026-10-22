<h1 align="center">🔍 leakwatch</h1>

<p align="center"><b>Find secrets that were ever committed to your git repo, even the ones you deleted.</b></p>

<p align="center">
  <a href="https://github.com/have-you-tried-restarting/leakwatch/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/have-you-tried-restarting/leakwatch/test.yml?style=for-the-badge&label=tests" alt="Tests"></a>
  <a href="https://github.com/have-you-tried-restarting/leakwatch/releases/latest"><img src="https://img.shields.io/github/v/release/have-you-tried-restarting/leakwatch?style=for-the-badge&color=D97757" alt="Release"></a>
  <img src="https://img.shields.io/badge/dependencies-none-2ea44f?style=for-the-badge" alt="No dependencies">
  <img src="https://img.shields.io/badge/python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.8+">
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-blue?style=for-the-badge" alt="MIT licence"></a>
</p>

Deleting a leaked key in a new commit doesn't remove it. It stays in your git history, and bots scrape GitHub for exactly that. leakwatch reads every line ever added, on every branch, and tells you what to revoke.

## See it work

You committed a key, then "removed" it:

```text
$ git log --oneline
b3f9a21 oops, remove the key
e805200 add deploy script 
```

```python
# deploy.py (in commit e805200)
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
```

Run leakwatch:

```text
$ python leakwatch.py

./my-project: Hardcoded credential in config.py (commit e805200b): Xk9$******
./my-project: AWS access key ID in deploy.py (commit e805200b): AKIA******

2 possible secret(s) found.
Revoke any real secret first. Removing it from git history does not make it safe again.
```

It still finds the key in the old commit. Secrets are never printed in full, so the output is safe to leave in CI logs. A clean repo looks like this:

```text
$ python leakwatch.py
No secrets found in history.
```

## Quick start

No `pip install`. You only need Python 3.8+ and git.

```bash
curl -O https://raw.githubusercontent.com/have-you-tried-restarting/leakwatch/main/leakwatch.py
python leakwatch.py                  # scan the repo in this folder
python leakwatch.py path/to/repo     # scan another repo
python leakwatch.py --github YOUR_USERNAME   # scan every non-fork repo on your account
```

Exit code: `0` clean, `1` secrets found, `2` error. That makes it easy to use in scripts.

## What it catches

| Type | Example |
| --- | --- |
| AWS access key ID | `AKIA…` |
| GitHub tokens | `ghp_…`, `github_pat_…` |
| Anthropic and OpenAI keys | `sk-ant-…`, `sk-…` |
| Slack, Stripe, Google keys | `xoxb-…`, `sk_live_…`, `AIza…` |
| Private keys | `-----BEGIN PRIVATE KEY-----` |
| Hardcoded credentials | `password = "Xk9$mQ2vLp7#wRt4"` |

Placeholders such as `changeme`, `your_key_here` or `example` are ignored. To silence a false positive, add `leakwatch:ignore` in a comment on that line.

## Add it to your repo

Fail the build when a secret shows up in your history:

```yaml
# .github/workflows/leakwatch.yml
name: leakwatch
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4 
        with:
          fetch-depth: 0        # needed so the whole history is scanned
      - uses: have-you-tried-restarting/leakwatch@v1
```

A failing run ends like this:

```text
Error: Process completed with exit code 1.
```

Inputs: `ignore-path` (a glob of files to skip) and `badge` (writes an SVG badge to that path).

## Badge

`python leakwatch.py --badge badge.svg` writes a small status badge you can commit and show in your README: green `secrets: clean`, or red `secrets: 2 leaked`.

## JSON output

For other tools, `--json` prints the findings as data:

```json
{
  "./my-project": [
    {
      "rule": "AWS access key ID",
      "file": "deploy.py",
      "commit": "e805200b",
      "preview": "AKIA******"
    }
  ]
}
```

## All options

| Flag | What it does |
| --- | --- |
| `--github USER` | Scan all non-fork repos of a GitHub user. Set `GITHUB_TOKEN` to include private repos and avoid rate limits. |
| `--ignore-path GLOB` | Skip matching files. Repeat for more. |
| `--json` | Print findings as JSON. |
| `--badge FILE` | Write an SVG status badge to FILE. |

## If it finds something

1. **Revoke the secret first.** Assume it's already stolen.
2. If you want, rewrite history with [git-filter-repo](https://github.com/newren/git-filter-repo). Rewriting alone does not make a leaked secret safe.

## Limits

Pattern matching can miss unusual formats and can flag harmless strings. A clean result is good news, not a guarantee. It scans only text added in commits, not binary files.

## Contributing

Ideas and bug reports are welcome: please [open an issue](../../issues). New detection rules that come with a test are especially useful.

## Licence

[MIT](LICENSE)

If leakwatch saved you from a leak, a ⭐ helps other people find it.
