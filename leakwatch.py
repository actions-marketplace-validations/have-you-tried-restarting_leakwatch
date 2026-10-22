#!/usr/bin/env python3
"""leakwatch: find secrets that were ever committed to a git repo. Standard library only."""
import argparse, base64, fnmatch, json, math, os, re, subprocess, sys, tempfile
import urllib.request

RULES = [
    ("Anthropic API key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{30,}")),
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{40,}")),
    ("AWS access key ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Slack token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}")),
    ("Stripe live key", re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b")),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY")),
]
GENERIC = re.compile(
    r"""(?i)(?:password|passwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*["']([^"'\s]{12,})["']"""
)
PLACEHOLDER = re.compile(r"(?i)example|placeholder|changeme|your[_-]|xxxx|<.*>|\$\{|\{\{|dummy|sample")


def entropy(s):
    return -sum(s.count(c) / len(s) * math.log2(s.count(c) / len(s)) for c in set(s))


def redact(s):
    return s[:4] + "*" * 6 if len(s) > 8 else "*" * 6


def scan_line(line):
    """Yield (rule, secret) for one added line."""
    if "leakwatch:ignore" in line:
        return
    found = set()
    for name, rx in RULES:
        for m in rx.finditer(line):
            if name == "OpenAI API key" and m.group().startswith("sk-ant-"):
                continue
            found.add(m.group())
            yield name, m.group()
    for m in GENERIC.finditer(line):
        v = m.group(1)
        if v not in found and not PLACEHOLDER.search(v) and entropy(v) > 3.3:
            yield "Hardcoded credential", v


def scan_repo(path, ignore_paths=()):
    """Scan every line ever added on any branch. Returns a list of findings."""
    cmd = ["git", "-C", path, "log", "--all", "-p", "-U0", "--no-color", "--no-ext-diff",
           "--format=@@commit %H"]
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    findings, seen = [], set()
    commit, fname = "", ""
    for raw in proc.stdout:
        line = raw.decode("utf-8", "replace").rstrip("\n")
        if line.startswith("@@commit "):
            commit = line[9:]
        elif line.startswith("+++ "):
            fname = line[6:] if line.startswith("+++ b/") else ""
        elif line.startswith("+") and fname:
            if any(fnmatch.fnmatch(fname, g) for g in ignore_paths):
                continue
            for rule, secret in scan_line(line[1:]):
                key = (rule, secret, fname)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({"rule": rule, "file": fname, "commit": commit[:8],
                                 "preview": redact(secret)})
    proc.stdout.close()
    err = proc.stderr.read().decode("utf-8", "replace")
    proc.stderr.close()
    if proc.wait() != 0:
        raise RuntimeError(err.strip() or "git log failed (is this a git repository?)")
    return findings


def badge_svg(count):
    label, value = "secrets", ("clean" if count == 0 else f"{count} leaked")
    color = "#2ea44f" if count == 0 else "#d73a49"
    lw, vw = 7 * len(label) + 12, 7 * len(value) + 12
    w = lw + vw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{label}: {value}">'
            f'<rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{vw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
            f'<text x="{lw / 2}" y="14">{label}</text><text x="{lw + vw / 2}" y="14">{value}</text></g></svg>')


def github_repos(user):
    token = os.environ.get("GITHUB_TOKEN")
    repos, page = [], 1
    while True:
        req = urllib.request.Request(
            f"https://api.github.com/users/{user}/repos?per_page=100&type=owner&page={page}",
            headers={"Accept": "application/vnd.github+json", **({"Authorization": f"Bearer {token}"} if token else {})})
        with urllib.request.urlopen(req) as r:
            batch = json.load(r)
        repos += [x for x in batch if not x["fork"]]
        if len(batch) < 100:
            return repos
        page += 1


def scan_github_user(user, ignore_paths):
    token = os.environ.get("GITHUB_TOKEN")
    auth = []
    if token:
        b = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        auth = ["-c", f"http.extraheader=Authorization: Basic {b}"]
    results = {}
    with tempfile.TemporaryDirectory() as tmp:
        for repo in github_repos(user):
            dest = os.path.join(tmp, repo["name"])
            r = subprocess.run(["git", *auth, "clone", "--bare", "-q", repo["clone_url"], dest],
                               capture_output=True)
            if r.returncode == 0:
                results[repo["full_name"]] = scan_repo(dest, ignore_paths)
    return results


def main(argv=None):
    p = argparse.ArgumentParser(description="Find secrets that were ever committed to a git repo.")
    p.add_argument("path", nargs="?", default=".", help="repo to scan (default: current directory)")
    p.add_argument("--github", metavar="USER", help="scan all non-fork repos of a GitHub user instead")
    p.add_argument("--ignore-path", action="append", default=[], metavar="GLOB", help="skip matching files")
    p.add_argument("--json", action="store_true", help="print findings as JSON")
    p.add_argument("--badge", metavar="FILE", help="write an SVG status badge to FILE")
    a = p.parse_args(argv)
    try:
        if a.github:
            results = scan_github_user(a.github, a.ignore_path)
        else:
            results = {os.path.abspath(a.path): scan_repo(a.path, a.ignore_path)}
    except (RuntimeError, OSError) as e:
        print(f"leakwatch: {e}", file=sys.stderr)
        return 2
    total = sum(len(f) for f in results.values())
    if a.badge:
        with open(a.badge, "w", encoding="utf-8") as fh:
            fh.write(badge_svg(total))
    if a.json:
        print(json.dumps(results, indent=2))
    else:
        for repo, findings in results.items():
            for f in findings:
                print(f"{repo}: {f['rule']} in {f['file']} (commit {f['commit']}): {f['preview']}")
        print(f"\n{total} possible secret(s) found." if total else "No secrets found in history.")
        if total:
            print("Revoke any real secret first. Removing it from git history does not make it safe again.")
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
