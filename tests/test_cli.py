import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from netguard.cli import main


class CliTests(unittest.TestCase):
    def test_demo_json(self):
        with tempfile.TemporaryDirectory() as state_dir:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["demo", "home-safe", "--no-notify", "--format", "json",
                             "--state-dir", state_dir])
            self.assertEqual(code, 0)
            payload = json.loads(buffer.getvalue())
            self.assertEqual(payload["verdict"]["level"], "SAFE")
            self.assertTrue(payload["simulated"])

    def test_demo_all_runs(self):
        with tempfile.TemporaryDirectory() as state_dir:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["demo", "--all", "--no-notify", "--format", "json",
                             "--state-dir", state_dir])
            self.assertEqual(code, 0)
            # One JSON object per scenario, back to back.
            decoder = json.JSONDecoder()
            text = buffer.getvalue().strip()
            count = 0
            index = 0
            while index < len(text):
                _, index = decoder.raw_decode(text, index)
                count += 1
                while index < len(text) and text[index].isspace():
                    index += 1
            self.assertEqual(count, 6)

    def test_checks_command(self):
        with tempfile.TemporaryDirectory() as state_dir:
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["checks", "--state-dir", state_dir])
            self.assertEqual(code, 0)
            self.assertIn("wifi_encryption", buffer.getvalue())

    def test_demo_save_html(self):
        with tempfile.TemporaryDirectory() as state_dir:
            output = f"{state_dir}/report.html"
            buffer = io.StringIO()
            with redirect_stdout(buffer):
                code = main(["demo", "cafe-open", "--no-notify", "--save-html", output,
                             "--state-dir", state_dir])
            self.assertEqual(code, 0)
            html = Path(output).read_text(encoding="utf-8")
            self.assertIn("CAUTION", html)


if __name__ == "__main__":
    unittest.main()
