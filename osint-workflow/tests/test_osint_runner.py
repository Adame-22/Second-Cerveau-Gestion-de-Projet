import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

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

    def test_accepts_phone(self):
        opts = runner.parse_args(["-m", "M1", "-p", "+33612345678", "-e", "a@b.com"])
        self.assertEqual(opts.phone, ["+33612345678"])

    def test_rejects_invalid_phone(self):
        with self.assertRaises(SystemExit):
            runner.parse_args(["-m", "M1", "-p", "abc"])


class PhoneTest(unittest.TestCase):
    def test_phone_lookup_valid_french(self):
        info = runner.run_phone_lookup("+33612345678")
        self.assertTrue(info.valid)
        self.assertIn("France", info.country)
        self.assertEqual(info.line_type, "mobile")

    def test_phone_lookup_invalid(self):
        info = runner.run_phone_lookup("+0000000")
        self.assertFalse(info.valid)


class CompanySearchTest(unittest.TestCase):
    def test_build_google_dorks_with_name(self):
        dorks = runner.build_google_dorks(nom="Jean Dupont", emails=["j@test.com"])
        labels = [d["label"] for d in dorks]
        self.assertIn("Nom complet", labels)
        self.assertIn("Nom + LinkedIn", labels)
        self.assertIn("Email j@test.com", labels)
        for d in dorks:
            self.assertIn("url", d)
            self.assertTrue(d["url"].startswith("https://"))

    def test_build_google_dorks_empty(self):
        dorks = runner.build_google_dorks()
        self.assertEqual(dorks, [])


class WhoisTest(unittest.TestCase):
    def test_whois_skips_free_providers(self):
        import tempfile
        raw_dir = Path(tempfile.mkdtemp())
        result = runner.run_whois_lookup("test@gmail.com", raw_dir)
        self.assertIsNone(result)


class ProfileExtractTest(unittest.TestCase):
    def test_extracts_profile_fields(self):
        runs = [
            runner.ToolRun("maigret", "bob", True, findings=[
                runner.Finding("bob", "username", "GitHub", "", ["maigret"],
                               {"fullname": "Bob Smith", "location": "Paris", "bio": "Developer"}),
                runner.Finding("bob", "username", "GitLab", "", ["maigret"],
                               {"fullname": "Bob Smith", "company": "ACME"}),
            ]),
            runner.ToolRun("sherlock", "bob", True, findings=[
                runner.Finding("bob", "username", "Twitter", "", ["sherlock"], {}),
            ]),
        ]
        details = runner.extract_profile_details(runs)
        self.assertEqual(details["fullname"], ["Bob Smith"])
        self.assertEqual(details["location"], ["Paris"])
        self.assertEqual(details["company"], ["ACME"])
        self.assertNotIn("age", details)


if __name__ == "__main__":
    unittest.main()
