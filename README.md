# leakwatch

Find secrets that were **ever** committed to your git repo, even ones you deleted later.

Deleting a leaked key in a new commit doesn't remove it. It stays in your history, and bots scrape GitHub for exactly that. leakwatch scans every line ever added on every branch and tells you what to revoke.

- **One file, no dependencies.** Just Python 3.8+ and git. No `pip install`.
- **Never prints a full secret.** Findings are redacted (`AKIA******`), so the output is safe to paste or leave in CI logs.
- **Catches the common stuff:** AWS, GitHub, Slack, Stripe, Google, OpenAI and Anthropic keys, private keys, and hardcoded `password = "..."` style credentials.
- **Use it three ways:** a CLI, a GitHub Action that fails your build, or a scan of every repo on your GitHub account.

## Use it

```bash
python leakwatch.py            # scan the repo in the current folder
python leakwatch.py path/to/repo
python leakwatch.py --github YOUR_USERNAME   # scan all your non-fork repos
```

Exit code is `1` if anything is found, `0` if clean and `2` on an error, so it works in scripts.

Scanning your account clones each repo temporarily. Set `GITHUB_TOKEN` to include private repos and avoid API rate limits.

## GitHub Action

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

Inputs: `ignore-path` (glob of files to skip) and `badge` (write an SVG badge to that path).

## Options

| Flag | What it does |
| --- | --- |
| `--ignore-path GLOB` | Skip matching files. Repeat for more. |
| `--json` | Print findings as JSON. |
| `--badge FILE` | Write an SVG status badge (`secrets: clean` or `N leaked`). |

To ignore a false positive, add `leakwatch:ignore` in a comment on that line.

## If it finds something

1. **Revoke the secret first.** Assume it's already stolen.
2. Then, if you want, rewrite history with [git-filter-repo](https://github.com/newren/git-filter-repo). Rewriting alone does not make a leaked secret safe.

## Limits

Pattern matching can miss unusual formats and can flag harmless strings. Treat a clean result as good news, not a guarantee. It scans only text added in commits, not binary files.

## Contributing

Ideas and bug reports are welcome: please [open an issue](../../issues). New detection rules that come with a test are especially useful.

## Licence

[MIT](LICENSE)
