import os, subprocess, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import leakwatch

# Built at runtime so this file never contains a scannable secret.
AWS = "AKIA" + "IOSFODNN7EXAMPL" + "E"
GH = "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"


def git(cwd, *args):
    subprocess.run(["git", "-C", cwd, "-c", "user.name=t", "-c", "user.email=t@t", *args],
                   check=True, capture_output=True)


class Scan(unittest.TestCase):
    def repo(self, tmp, content):
        git(tmp, "init", "-q")
        with open(os.path.join(tmp, "a.txt"), "w") as f:
            f.write(content)
        git(tmp, "add", "."); git(tmp, "commit", "-qm", "x")

    def test_finds_secret_even_after_deletion(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo(tmp, f"key={AWS}\ntoken={GH}\n")
            open(os.path.join(tmp, "a.txt"), "w").close()
            git(tmp, "commit", "-qam", "remove")
            rules = {f["rule"] for f in leakwatch.scan_repo(tmp)}
            self.assertEqual(rules, {"AWS access key ID", "GitHub token"})

    def test_output_is_redacted(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo(tmp, f"key={AWS}\n")
            self.assertNotIn(AWS, str(leakwatch.scan_repo(tmp)))

    def test_clean_repo_and_ignore_marker(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo(tmp, f"hello\nkey={AWS}  # leakwatch:ignore\npassword = 'changeme-example'\n")
            self.assertEqual(leakwatch.scan_repo(tmp), [])

    def test_generic_credential(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.repo(tmp, 'db_password = "Xk9$mQ2vLp7#wRt4"\n')
            self.assertEqual(leakwatch.scan_repo(tmp)[0]["rule"], "Hardcoded credential")

    def test_badge_and_exit_codes(self):
        self.assertIn("clean", leakwatch.badge_svg(0))
        self.assertIn("2 leaked", leakwatch.badge_svg(2))
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(leakwatch.main([tmp]), 2)  # not a git repo


if __name__ == "__main__":
    unittest.main()
