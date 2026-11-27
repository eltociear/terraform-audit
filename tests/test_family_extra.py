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



class ScriptRefEquivalence(unittest.TestCase):
    """The linear script-reference finder must agree with the original regex."""

    def test_fuzz_against_regex(self):
        import random
        rnd = random.Random(1)
        alpha = list("ab.-/_${}x ") + ["sh", "py", ".sh", ".py", ".ps1", ".psm1", ".bash", "\n", "=", '"']
        for _ in range(5000):
            s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 40)))
            want = [(m.group(1), m.group(2), m.start()) for m in ta._SCRIPT_REF.finditer(s)]
            got = [(m.group(1), m.group(2), m.start()) for m in ta.SCRIPT_REF_RE.finditer(s)]
            self.assertEqual(got, want, repr(s))

    def test_long_word_run_is_linear(self):
        s = ("a" * 300 + ".x ") * 20000
        t0 = time.time()
        list(ta.SCRIPT_REF_RE.finditer(s))
        self.assertLess(time.time() - t0, 30)


class BoundedPatterns(unittest.TestCase):
    def test_rewrites_match_the_same_strings(self):
        import random
        import re
        rnd = random.Random(3)
        alpha = ["iex", " ", "(", "Invoke-Expression", "iwr", "irm", "\n", "x", "New-Object Net.WebClient",
                 "curl ", "-k", "\t", "--insecure"]
        pats = [p for g in ta.PATTERNS.values() for pg in g for p in pg["regexes"] if ta._BOUND(p) != p]
        self.assertTrue(pats)
        for p in pats:
            a, b = re.compile(p, re.I), re.compile(ta._BOUND(p), re.I)
            for _ in range(1000):
                s = "".join(rnd.choice(alpha) for _ in range(rnd.randint(0, 15)))
                self.assertEqual([m.span() for m in a.finditer(s)], [m.span() for m in b.finditer(s)], (p, s))

    def test_whitespace_padded_iex_is_linear(self):
        s = ("IEX(" + " " * 50 + "aaaa((((" + " " * 50) * 2000
        t0 = time.time()
        ta.scan_module({"x.py": s}, "x.py", True)
        self.assertLess(time.time() - t0, 60)


if __name__ == "__main__":
    unittest.main()
