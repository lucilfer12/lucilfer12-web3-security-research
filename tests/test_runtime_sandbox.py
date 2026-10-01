import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from w3sec.runtime import _sandbox_command


class RuntimeSandbox(unittest.TestCase):
    def test_bwrap_wraps_command_without_network_and_hides_home(self):
        with tempfile.TemporaryDirectory() as td:
            cwd = Path(td)
            with patch("w3sec.runtime._HOST_IS_WINDOWS", False), patch(
                "w3sec.runtime.shutil.which",
                side_effect=lambda name, path=None: "/usr/bin/bwrap" if name == "bwrap" else None,
            ):
                wrapped = _sandbox_command(
                    ("python", "-m", "pytest", "-q"),
                    cwd=cwd,
                    env={"PATH": "/usr/bin", "ATLAS_EXECUTION_SANDBOX": "bwrap"},
                )
        self.assertEqual("/usr/bin/bwrap", wrapped[0])
        self.assertIn("--unshare-all", wrapped)
        self.assertIn("--new-session", wrapped)
        self.assertIn("--tmpfs", wrapped)
        self.assertIn("/home", wrapped)
        self.assertIn("/atlas-work", wrapped)
        self.assertEqual(
            ("python", "-m", "pytest", "-q"),
            tuple(wrapped[wrapped.index("--") + 1 :]),
        )
        self.assertIn("--unshare-all", wrapped)

    def test_bwrap_requires_installed_runner(self):
        with tempfile.TemporaryDirectory() as td:
            with patch("w3sec.runtime._HOST_IS_WINDOWS", False), patch(
                "w3sec.runtime.shutil.which", return_value=None
            ):
                with self.assertRaises(RuntimeError):
                    _sandbox_command(
                        ("python", "-m", "pytest"),
                        cwd=Path(td),
                        env={"PATH": "/usr/bin", "ATLAS_EXECUTION_SANDBOX": "bwrap"},
                    )

    def test_without_bwrap_mode_command_is_unchanged(self):
        with tempfile.TemporaryDirectory() as td:
            command = ("python", "-m", "pytest", "-q")
            with patch("w3sec.runtime.os.name", "posix"):
                self.assertEqual(
                    command,
                    _sandbox_command(command, cwd=Path(td), env={"PATH": "/usr/bin"}),
                )


if __name__ == "__main__":
    unittest.main()
