import sys
import time
import unittest
from pathlib import Path

from w3sec.runtime import run_bounded


class BoundedRunDescendantPipe(unittest.TestCase):
    def test_timeout_does_not_close_pipe_while_descendant_holds_it(self):
        child = (
            "import time; "
            "print('child-alive', flush=True); "
            "time.sleep(4)"
        )
        parent = (
            "import subprocess,sys,time; "
            f"subprocess.Popen([sys.executable, '-c', {child!r}]); "
            "print('parent-alive', flush=True); "
            "time.sleep(5)"
        )
        start = time.monotonic()
        result = run_bounded(
            (sys.executable, "-c", parent),
            cwd=Path.cwd(),
            timeout=0.5,
            max_output_bytes=65536,
        )
        elapsed = time.monotonic() - start

        self.assertTrue(result.timed_out)
        self.assertLess(elapsed, 3.0)
        self.assertIn("parent-alive", result.stdout)


if __name__ == "__main__":
    unittest.main()
