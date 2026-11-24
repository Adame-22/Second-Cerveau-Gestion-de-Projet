import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import osint_runner as runner


class ParsersTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def test_holehe_csv_separates_found_checked_and_rate_limited(self):
        path = self.tmp / "holehe.csv"
        path.write_text(
            "name,domain,method,frequent_rate_limit,rateLimit,exists,emailrecovery,phoneNumber,others\n"
            "spotify,spotify.com,register,False,False,True,,,\n"
            "adobe,adobe.com,password recovery,False,False,True,a***@gmail.com,,\n"
            "amazon,amazon.com,login,False,True,False,,,\n"
            "github,github.com,register,False,False,False,,,\n",
            encoding="utf-8",
        )
        findings, checked, rate_limited = runner.parse_holehe_csv(path, "a@b.fr")
        self.assertEqual([f.site for f in findings], ["spotify", "adobe"])
        self.assertEqual((checked, rate_limited), (3, 1))
        self.assertEqual(findings[1].details, {"email de secours (partiel)": "a***@gmail.com"})

    def test_sherlock_output_keeps_only_found_lines(self):
        output = (
            "[*] Checking username bob on:\n"
            "[+] GitHub: https://github.com/bob\n"
            "[-] Reddit: Not Found!\n"
            "[+] Hacker News: https://news.ycombinator.com/user?id=bob\n"
            "[*] Search completed with 2 results\n"
        )
        findings = runner.parse_sherlock_output(output, "bob")
        self.assertEqual([(f.site, f.url) for f in findings], [
            ("GitHub", "https://github.com/bob"),
            ("Hacker News", "https://news.ycombinator.com/user?id=bob"),
        ])

    def test_maigret_json_keeps_claimed_and_collects_leads(self):
        path = self.tmp / "report_bob_simple.json"
        path.write_text(json.dumps({
            "GitLab": {
                "url_user": "https://gitlab.com/bob",
                "ids_usernames": {"bob": "username", "bobby42": "username"},
                "status": {"status": "Claimed", "ids": {"fullname": "Bob", "image": "http://x/y.png"}},
            },
            "Other": {"url_user": "https://other/bob", "status": {"status": "Available"}},
        }), encoding="utf-8")
        findings, leads = runner.parse_maigret_json(path, "bob")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].details, {"fullname": "Bob"})
        self.assertEqual(leads, ["bobby42 (username, vu sur GitLab)"])

    def test_merge_combines_sources_for_same_site(self):
        runs = [
            runner.ToolRun("sherlock", "bob", True, findings=[
                runner.Finding("bob", "username", "GitHub", "https://github.com/bob", ["sherlock"])]),
            runner.ToolRun("maigret", "bob", True, findings=[
                runner.Finding("bob", "username", "Github", "https://github.com/bob", ["maigret"], {"uid": "1"})]),
        ]
        merged = runner.merge_findings(runs)
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].sources, ["maigret", "sherlock"])
        self.assertEqual(merged[0].details, {"uid": "1"})


class ArgsTest(unittest.TestCase):
    def test_rejects_option_like_username_and_missing_mandat(self):
        for argv in (["--mandat", "M1", "-u", "-a"], ["--mandat", "M1", "-e", "pas-un-email"], ["-u", "bob"]):
            with self.assertRaises(SystemExit):
                runner.parse_args(argv)

    def test_accepts_repeated_identifiers(self):
        opts = runner.parse_args(["-m", "M1", "-u", "bob", "-u", "bob_2", "-e", "a.b+c@mail.fr"])
        self.assertEqual(opts.username, ["bob", "bob_2"])
        self.assertEqual(opts.email, ["a.b+c@mail.fr"])


if __name__ == "__main__":
    unittest.main()
