import tempfile
import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secret_scanner import DEFAULT_IGNORES, mask, scan, scan_file


class SecretScannerTests(unittest.TestCase):
    def test_masks_without_exposing_full_value(self):
        self.assertEqual(mask("abcdefghijk"), "abcd…hijk")
        self.assertEqual(mask("short"), "*****")

    def test_detects_and_redacts_github_token(self):
        with tempfile.TemporaryDirectory() as temp:
            source = Path(temp) / "settings.py"
            source.write_text("token = 'ghp_abcdefghijklmnopqrstuvwxyz123456'\n", encoding="utf-8")
            findings = scan_file(source)
            self.assertEqual(findings[0].rule, "GitHub token")
            self.assertNotIn("abcdefghijklmnopqrstuvwxyz", findings[0].preview)

    def test_ignores_git_directory_and_binary_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / ".git").mkdir()
            (root / ".git" / "config").write_text("password=super-secret-value", encoding="utf-8")
            (root / "binary.bin").write_bytes(b"\x00password=super-secret-value")
            (root / "app.env").write_text("API_KEY=abcdefgh123456", encoding="utf-8")
            findings = scan(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].path.name, "app.env")

    def test_default_ignore_contains_git(self):
        self.assertIn(".git", DEFAULT_IGNORES)


if __name__ == "__main__":
    unittest.main()

