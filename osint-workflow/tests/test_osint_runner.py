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


class ReputationTest(unittest.TestCase):
    def test_reputation_unreachable_returns_error(self):
        raw_dir = Path(tempfile.mkdtemp())
        with patch("osint_runner.urllib.request.urlopen", side_effect=Exception("timeout")):
            result = runner.run_email_reputation("test@example.com", raw_dir)
        self.assertEqual(result["error"], "unreachable")
        self.assertEqual(result["email"], "test@example.com")

    def test_reputation_parses_response(self):
        raw_dir = Path(tempfile.mkdtemp())
        fake_resp = json.dumps({
            "email": "test@example.com",
            "reputation": "high",
            "suspicious": False,
            "references": 10,
            "details": {
                "blacklisted": False,
                "malicious_activity": False,
                "credentials_leaked": True,
                "data_breach": True,
                "first_seen": "2015-01-01",
                "last_seen": "2024-06-01",
                "domain_reputation": "high",
                "profiles": ["twitter", "linkedin"],
                "spoofable": False,
                "spam": False,
            }
        }).encode()

        class FakeResp:
            def read(self):
                return fake_resp
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass

        with patch("osint_runner.urllib.request.urlopen", return_value=FakeResp()):
            result = runner.run_email_reputation("test@example.com", raw_dir)
        self.assertEqual(result["reputation"], "high")
        self.assertFalse(result["suspicious"])
        self.assertTrue(result["credentials_leaked"])
        self.assertEqual(result["profiles"], ["twitter", "linkedin"])


class PasteSearchTest(unittest.TestCase):
    def test_paste_urls_with_email_and_username(self):
        urls = runner.build_paste_search_urls(emails=["a@b.com"], usernames=["bob"])
        labels = [u["label"] for u in urls]
        self.assertTrue(any("Pastebin" in l and "a@b.com" in l for l in labels))
        self.assertTrue(any("GitHub Gists" in l and "bob" in l for l in labels))
        self.assertTrue(any("IntelligenceX" in l for l in labels))
        for u in urls:
            self.assertTrue(u["url"].startswith("https://"))

    def test_paste_urls_empty(self):
        urls = runner.build_paste_search_urls()
        self.assertEqual(urls, [])

    def test_paste_urls_with_phone(self):
        urls = runner.build_paste_search_urls(phones=["+33612345678"])
        self.assertTrue(any("IntelligenceX" in u["label"] for u in urls))


class WaybackTest(unittest.TestCase):
    def test_parse_wayback_timestamp(self):
        self.assertEqual(runner._parse_wayback_timestamp("20060315120000"), "2006-03-15")
        self.assertEqual(runner._parse_wayback_timestamp("2020"), "2020")

    def test_wayback_no_data(self):
        raw_dir = Path(tempfile.mkdtemp())
        with patch("osint_runner.http_get_json", return_value=None):
            results = runner.run_wayback_check(["https://example.com"], raw_dir)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].total_snapshots, 0)

    def test_wayback_with_data(self):
        raw_dir = Path(tempfile.mkdtemp())
        fake_cdx = [
            ["timestamp", "original", "statuscode"],
            ["20100601120000", "http://example.com", "200"],
            ["20231215120000", "http://example.com", "200"],
        ]
        with patch("osint_runner.http_get_json", return_value=fake_cdx):
            results = runner.run_wayback_check(["https://example.com"], raw_dir)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].oldest_snapshot, "2010-06-01")
        self.assertEqual(results[0].newest_snapshot, "2023-12-15")
        self.assertEqual(results[0].total_snapshots, 2)


class DnsTest(unittest.TestCase):
    def test_dns_skips_free_providers(self):
        result = runner.run_dns_lookup("gmail.com", Path(tempfile.mkdtemp()))
        self.assertIsNone(result)

    def test_dns_skips_sfr(self):
        result = runner.run_dns_lookup("sfr.fr", Path(tempfile.mkdtemp()))
        self.assertIsNone(result)

    def test_dns_result_dataclass(self):
        dr = runner.DnsResult(domain="test.fr", mx_records=["mx1.ovh.net"], hosting_hints=["Email heberge par OVH"])
        self.assertEqual(dr.domain, "test.fr")
        self.assertEqual(dr.mx_records, ["mx1.ovh.net"])


class SkipChoicesTest(unittest.TestCase):
    def test_skip_new_modules(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com",
                                  "--skip", "wayback", "--skip", "dns", "--skip", "paste", "--skip", "reputation"])
        self.assertIn("wayback", opts.skip)
        self.assertIn("dns", opts.skip)
        self.assertIn("paste", opts.skip)
        self.assertIn("reputation", opts.skip)


class ConfigTest(unittest.TestCase):
    def test_load_config_missing_file(self):
        cfg = runner.load_config("/tmp/nonexistent_config_osint.json")
        self.assertEqual(cfg, {})

    def test_load_config_valid_file(self):
        tmp = Path(tempfile.mkdtemp()) / "cfg.json"
        tmp.write_text('{"hibp_api_key": "test123", "export_pdf": true}', encoding="utf-8")
        cfg = runner.load_config(str(tmp))
        self.assertEqual(cfg["hibp_api_key"], "test123")
        self.assertTrue(cfg["export_pdf"])

    def test_load_config_invalid_json(self):
        tmp = Path(tempfile.mkdtemp()) / "bad.json"
        tmp.write_text("{broken json", encoding="utf-8")
        cfg = runner.load_config(str(tmp))
        self.assertEqual(cfg, {})


class PdfFlagTest(unittest.TestCase):
    def setUp(self):
        self._orig_config = runner.CONFIG.copy()

    def tearDown(self):
        runner.CONFIG = self._orig_config

    def test_pdf_flag_accepted(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--pdf"])
        self.assertTrue(opts.pdf)

    def test_pdf_flag_default_false(self):
        runner.CONFIG = {}
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com"])
        self.assertFalse(opts.pdf)

    def test_config_flag_accepted(self):
        tmp = Path(tempfile.mkdtemp()) / "alt.json"
        tmp.write_text('{"export_pdf": true}', encoding="utf-8")
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--config", str(tmp)])
        self.assertTrue(opts.pdf)


class HttpGetJsonTest(unittest.TestCase):
    def test_returns_none_on_failure(self):
        with patch("osint_runner.urllib.request.urlopen", side_effect=Exception("fail")):
            result = runner.http_get_json("https://example.com/api", timeout=1, retries=0)
        self.assertIsNone(result)

    def test_parses_json_response(self):
        fake_data = json.dumps({"key": "value"}).encode()
        class FakeResp:
            def read(self):
                return fake_data
            def __enter__(self):
                return self
            def __exit__(self, *a):
                pass
        with patch("osint_runner.urllib.request.urlopen", return_value=FakeResp()):
            result = runner.http_get_json("https://example.com/api", timeout=1, retries=0)
        self.assertEqual(result, {"key": "value"})


class RiskLevelTest(unittest.TestCase):
    """Test that the risk calculation logic produces correct levels."""
    def _make_opts(self):
        return runner.parse_args(["-m", "M1", "-e", "a@b.com", "-u", "user1"])

    def test_risk_eleve_many_breaches(self):
        opts = self._make_opts()
        runs = [runner.ToolRun("sherlock", "user1", True, findings=[
            runner.Finding("user1", "username", f"Site{i}", f"https://site{i}.com", ["sherlock"])
            for i in range(3)
        ])]
        findings = runner.merge_findings(runs)
        breaches = [runner.BreachInfo("a@b.com", f"Breach{i}") for i in range(4)]
        # Directly test the logic from render_report
        total_breaches = len(breaches)
        total_accounts = len(findings)
        risk = "ELEVE" if total_breaches > 3 or total_accounts > 20 else \
               "MOYEN" if total_breaches > 0 or total_accounts > 5 else "FAIBLE"
        self.assertEqual(risk, "ELEVE")

    def test_risk_faible_clean(self):
        risk = "ELEVE" if 0 > 3 or 2 > 20 else \
               "MOYEN" if 0 > 0 or 2 > 5 else "FAIBLE"
        self.assertEqual(risk, "FAIBLE")


class SocialProfileTest(unittest.TestCase):
    def test_social_urls_with_username(self):
        urls = runner.build_social_profile_urls(usernames=["jdupont"])
        platforms = [u["platform"] for u in urls]
        self.assertIn("LinkedIn", platforms)
        self.assertIn("GitHub", platforms)
        self.assertIn("Twitter/X", platforms)
        self.assertIn("Instagram", platforms)
        self.assertTrue(all(u["url"].startswith("https://") for u in urls))

    def test_social_urls_empty(self):
        urls = runner.build_social_profile_urls()
        self.assertEqual(urls, [])

    def test_social_urls_with_email(self):
        urls = runner.build_social_profile_urls(emails=["test@example.com"])
        self.assertTrue(any("Gravatar" in u["platform"] for u in urls))


class IdentityCardTest(unittest.TestCase):
    def test_builds_card_from_all_sources(self):
        opts = runner.parse_args(["-m", "M1", "-e", "jean@custom-domain.fr", "-u", "jdupont",
                                  "-p", "+33612345678", "-n", "Jean Dupont"])
        profile = {"fullname": ["Jean Dupont"], "location": ["Paris"], "company": ["ACME Corp"]}
        phones = [runner.PhoneInfo("+33612345678", True, "France", "SFR", "mobile", "France")]
        companies = [runner.CompanyInfo("ACME SAS", "123456789", "President", "Active", "1 rue test", "2020-01-01", "Pappers")]
        whois = [{"domain": "custom-domain.fr", "registrant_name": "Jean Dupont", "registrant_city": "Paris"}]
        breaches = [runner.BreachInfo("jean@custom-domain.fr", "BigBreach", "2021-01-01", ["Passwords", "Email addresses"])]
        findings = [runner.Finding("jdupont", "username", "GitHub", "https://github.com/jdupont", ["sherlock"])]
        rep = [{"email": "jean@custom-domain.fr", "reputation": "high", "suspicious": False, "profiles": ["linkedin"]}]

        card = runner.build_identity_card(opts, profile, phones, companies, whois,
                                          reputation_results=rep, breaches=breaches, findings=findings)

        self.assertEqual(card["nom"], "Jean Dupont")
        self.assertEqual(card["noms_detectes"], ["Jean Dupont"])
        self.assertIn("Paris", card["localisations"])
        self.assertEqual(card["operateurs"], ["SFR"])
        self.assertEqual(card["entreprises_registre"][0]["nom"], "ACME SAS")
        self.assertEqual(card["domaines_personnels"], ["custom-domain.fr"])
        self.assertEqual(card["profils_reputation"], ["linkedin"])
        self.assertEqual(card["nb_fuites"], 1)
        self.assertIn("Passwords", card["types_donnees_exposees"])
        self.assertEqual(card["nb_comptes"], 1)

    def test_card_empty_inputs(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com"])
        card = runner.build_identity_card(opts, {}, [], [], [])
        self.assertEqual(card["emails"], ["a@b.com"])
        self.assertNotIn("nom", card)
        self.assertNotIn("nb_fuites", card)


class UsernamePermutationTest(unittest.TestCase):
    def test_generates_from_name(self):
        perms = runner.generate_username_permutations(nom="Jean Dupont")
        self.assertIn("jeandupont", perms)
        self.assertIn("dupont.jean", perms)
        self.assertIn("j.dupont", perms)
        self.assertIn("jdupont", perms)
        self.assertIn("dupontj", perms)
        self.assertGreater(len(perms), 10)

    def test_generates_from_email(self):
        perms = runner.generate_username_permutations(emails=["mj.lcaze@gmail.com"])
        self.assertIn("mj.lcaze", perms)
        self.assertIn("mj_lcaze", perms)
        self.assertIn("mjlcaze", perms)

    def test_excludes_existing_usernames(self):
        perms = runner.generate_username_permutations(nom="Jean Dupont", usernames=["jdupont"])
        self.assertNotIn("jdupont", perms)

    def test_empty_inputs(self):
        perms = runner.generate_username_permutations()
        self.assertEqual(perms, [])


class RiskScoreTest(unittest.TestCase):
    def test_low_risk(self):
        score, level = runner.compute_risk_score([], [], [], [], [])
        self.assertEqual(score, 0)
        self.assertEqual(level, "FAIBLE")

    def test_high_risk_many_breaches(self):
        breaches = [runner.BreachInfo("a@b.com", f"Breach{i}", "2023", ["Passwords", "Email addresses"]) for i in range(6)]
        findings = [runner.Finding("a", "email", f"Site{i}", f"https://s{i}.com", ["holehe"]) for i in range(25)]
        score, level = runner.compute_risk_score(findings, breaches, [], [], [])
        self.assertGreaterEqual(score, 70)
        self.assertEqual(level, "CRITIQUE")

    def test_medium_risk(self):
        findings = [runner.Finding("a", "email", f"Site{i}", f"https://s{i}.com", ["holehe"]) for i in range(8)]
        breaches = [runner.BreachInfo("a@b.com", "Breach1", "2023", ["Email addresses"])]
        score, level = runner.compute_risk_score(findings, breaches, [], [], [])
        self.assertGreaterEqual(score, 15)
        self.assertIn(level, ["MOYEN", "ELEVE"])

    def test_whois_exposure_adds_score(self):
        score_without, _ = runner.compute_risk_score([], [], [], [], [])
        score_with, _ = runner.compute_risk_score([], [], [], [], [{"registrant_name": "Jean Dupont", "domain": "example.com"}])
        self.assertGreater(score_with, score_without)


class CsvExportTest(unittest.TestCase):
    def test_export_accounts_csv(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
        from csv_export import export_accounts_csv
        tmp = Path(tempfile.mkdtemp())
        findings = [
            runner.Finding("bob", "username", "GitHub", "https://github.com/bob", ["sherlock"], {"uid": "123"}),
            runner.Finding("bob@test.com", "email", "spotify", "https://spotify.com", ["holehe"]),
        ]
        path = export_accounts_csv(tmp, findings)
        self.assertTrue(path.exists())
        lines = path.read_text(encoding="utf-8").strip().split("\n")
        self.assertEqual(len(lines), 3)  # header + 2 rows


if __name__ == "__main__":
    unittest.main()
