"""One-line (minified / padded) scripts must scan in linear time."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import terraform_audit as ta  # noqa: E402


class LongLine(unittest.TestCase):
    def test_curl_dense_line_is_linear(self):
        line = ("curl https://x.invalid/a -o a; eval(atob('aGk=')); " * 40000)[:2000000]
        t0 = time.time()
        r = ta.scan_module({"x.sh": line}, "x.sh", True)
        self.assertLess(time.time() - t0, 60)   # was O(n^2): ~0.7 s per 100 kB, 2 MB never finished
        self.assertIn("risk_level", r)


if __name__ == "__main__":
    unittest.main()
