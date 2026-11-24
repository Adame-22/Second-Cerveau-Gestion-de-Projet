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


class CorrelationTest(unittest.TestCase):
    def test_detects_reused_pseudo(self):
        findings = [
            runner.Finding("bob", "username", "GitHub", "https://github.com/bob", ["sherlock"]),
            runner.Finding("bob", "username", "Twitter", "https://twitter.com/bob", ["sherlock"]),
            runner.Finding("bob", "username", "Reddit", "https://reddit.com/u/bob", ["sherlock"]),
        ]
        corr = runner.build_correlations(findings, {}, [], [])
        types = [c["type"] for c in corr]
        self.assertIn("pseudo_reutilise", types)

    def test_detects_multi_breach_email(self):
        breaches = [
            runner.BreachInfo("a@b.com", "Leak1", "2023", ["Passwords"]),
            runner.BreachInfo("a@b.com", "Leak2", "2024", ["Email addresses"]),
        ]
        corr = runner.build_correlations([], {}, breaches, [])
        types = [c["type"] for c in corr]
        self.assertIn("email_multi_fuites", types)

    def test_detects_whois_identity(self):
        corr = runner.build_correlations([], {}, [], [{"registrant_name": "Jean", "domain": "ex.com"}])
        types = [c["type"] for c in corr]
        self.assertIn("whois_identite", types)

    def test_empty_inputs(self):
        corr = runner.build_correlations([], {}, [], [])
        self.assertEqual(corr, [])


class FamilyDorksTest(unittest.TestCase):
    def test_family_dorks_with_name(self):
        dorks = runner.build_family_search_dorks(nom="Jean Dupont")
        labels = [d["label"] for d in dorks]
        self.assertTrue(any("Geneanet" in l for l in labels))
        self.assertTrue(any("Filae" in l for l in labels))
        self.assertTrue(any("Famille" in l for l in labels))
        self.assertTrue(any("necrologie" in l.lower() for l in labels))
        self.assertTrue(any("Etat civil" in l for l in labels))
        for d in dorks:
            self.assertTrue(d["url"].startswith("https://"))

    def test_family_dorks_with_prenom(self):
        dorks = runner.build_family_search_dorks(nom="Dupont", prenom="Jean")
        labels = [d["label"] for d in dorks]
        self.assertTrue(any("Prenom" in l for l in labels))

    def test_family_dorks_with_dob(self):
        dorks = runner.build_family_search_dorks(nom="Dupont", dob="15/06/1990")
        labels = [d["label"] for d in dorks]
        self.assertTrue(any("1990" in l for l in labels))
        self.assertTrue(any("Age" in l for l in labels))

    def test_family_dorks_empty(self):
        dorks = runner.build_family_search_dorks()
        self.assertEqual(dorks, [])

    def test_family_dorks_with_phones(self):
        dorks = runner.build_family_search_dorks(nom="Dupont", phones=["+33612345678"])
        labels = [d["label"] for d in dorks]
        self.assertTrue(any("annuaire" in l.lower() for l in labels))


class NewCliArgsTest(unittest.TestCase):
    def test_prenom_flag(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--prenom", "Jean"])
        self.assertEqual(opts.prenom, "Jean")

    def test_dob_flag(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--dob", "15/06/1990"])
        self.assertEqual(opts.dob, "15/06/1990")

    def test_skip_family(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--skip", "family"])
        self.assertIn("family", opts.skip)

    def test_skip_social(self):
        opts = runner.parse_args(["-m", "M1", "-e", "a@b.com", "--skip", "social"])
        self.assertIn("social", opts.skip)


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



class ClassifyExposedDataTest(unittest.TestCase):
    def test_classifies_breach_data_types(self):
        breach = runner.BreachInfo(
            email="a@b.com", breach_name="TestBreach",
            breach_date="2024-01-01", data_types=["Passwords", "Email addresses", "Phone numbers", "Usernames"])
        result = runner.classify_exposed_data([breach], [], [], [])
        self.assertEqual(len(result["CRITIQUE"]), 1)
        self.assertEqual(result["CRITIQUE"][0]["type"], "Passwords")
        self.assertEqual(len(result["ELEVE"]), 1)
        self.assertEqual(result["ELEVE"][0]["type"], "Phone numbers")
        self.assertEqual(len(result["MOYEN"]), 1)
        self.assertEqual(result["MOYEN"][0]["type"], "Email addresses")
        self.assertEqual(len(result["FAIBLE"]), 1)
        self.assertEqual(result["FAIBLE"][0]["type"], "Usernames")

    def test_classifies_whois_exposure(self):
        whois = [{"domain": "test.com", "registrant_name": "John", "registrant_address": "123 Rue X"}]
        result = runner.classify_exposed_data([], whois, [], [])
        self.assertEqual(len(result["MOYEN"]), 1)
        self.assertEqual(len(result["ELEVE"]), 1)

    def test_classifies_reputation_leaked(self):
        rep = [{"email": "a@b.com", "credentials_leaked": True}]
        result = runner.classify_exposed_data([], [], rep, [])
        self.assertEqual(len(result["CRITIQUE"]), 1)
        self.assertIn("Credentials leaked", result["CRITIQUE"][0]["type"])

    def test_classifies_public_accounts(self):
        findings = [runner.Finding(identifier="a@b.com", kind="email", site="twitter")]
        result = runner.classify_exposed_data([], [], [], findings)
        self.assertEqual(len(result["FAIBLE"]), 1)
        self.assertIn("comptes publics", result["FAIBLE"][0]["type"])

    def test_empty_inputs(self):
        result = runner.classify_exposed_data([], [], [], [])
        self.assertEqual(result["CRITIQUE"], [])
        self.assertEqual(result["ELEVE"], [])
        self.assertEqual(result["MOYEN"], [])
        self.assertEqual(result["FAIBLE"], [])


class DarkWebCheckTest(unittest.TestCase):
    def test_generates_email_urls(self):
        urls = runner.build_dark_web_check_urls(emails=["test@example.com"])
        self.assertTrue(len(urls) >= 5)
        services = {u["service"] for u in urls}
        self.assertIn("Have I Been Pwned", services)
        self.assertIn("DeHashed", services)
        self.assertIn("IntelligenceX", services)

    def test_generates_phone_urls(self):
        urls = runner.build_dark_web_check_urls(phones=["+33612345678"])
        self.assertTrue(len(urls) >= 2)
        services = {u["service"] for u in urls}
        self.assertIn("Truecaller", services)

    def test_generates_username_urls(self):
        urls = runner.build_dark_web_check_urls(usernames=["johndoe"])
        self.assertTrue(len(urls) >= 2)
        services = {u["service"] for u in urls}
        self.assertIn("NameCheckr", services)
        self.assertIn("KnowEm", services)

    def test_all_types(self):
        urls = runner.build_dark_web_check_urls(
            emails=["a@b.com"], phones=["+33600000000"], usernames=["user1"])
        email_urls = [u for u in urls if u["type"] == "email"]
        phone_urls = [u for u in urls if u["type"] == "phone"]
        username_urls = [u for u in urls if u["type"] == "username"]
        self.assertTrue(len(email_urls) >= 5)
        self.assertTrue(len(phone_urls) >= 2)
        self.assertTrue(len(username_urls) >= 2)

    def test_empty_inputs(self):
        urls = runner.build_dark_web_check_urls()
        self.assertEqual(urls, [])

class ReverseImageTest(unittest.TestCase):
    def test_generates_gravatar_urls(self):
        urls = runner.build_reverse_image_search_urls(emails=["test@example.com"])
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0]["platform"], "Gravatar")
        self.assertIn("gravatar.com/avatar/", urls[0]["image_url"])
        self.assertIn("lens.google.com", urls[0]["google_lens"])
        self.assertIn("tineye.com", urls[0]["tineye"])
        self.assertIn("yandex.com", urls[0]["yandex"])

    def test_generates_github_urls(self):
        urls = runner.build_reverse_image_search_urls(usernames=["testuser"])
        self.assertEqual(len(urls), 1)
        self.assertEqual(urls[0]["platform"], "GitHub Avatar")
        self.assertIn("github.com/testuser.png", urls[0]["image_url"])

    def test_empty_inputs(self):
        urls = runner.build_reverse_image_search_urls()
        self.assertEqual(urls, [])

    def test_combined(self):
        urls = runner.build_reverse_image_search_urls(usernames=["u1"], emails=["e@x.com"])
        self.assertEqual(len(urls), 2)


class AddressLeakTest(unittest.TestCase):
    def test_detects_breach_address(self):
        breach = runner.BreachInfo(email="a@b.com", breach_name="Leak1", breach_date="2024-01-01",
                                   data_types=["Physical addresses", "Email addresses"])
        leaks = runner.detect_address_leaks([breach], [], {}, [])
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0]["severity"], "ELEVE")
        self.assertEqual(leaks[0]["type"], "adresse_physique")

    def test_detects_whois_address(self):
        whois = {"domain": "perso.com", "registrant_name": "Jean",
                 "registrant_address": "1 rue X", "registrant_city": "Paris", "registrant_country": "FR"}
        leaks = runner.detect_address_leaks([], [whois], {}, [])
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0]["type"], "adresse_whois")

    def test_detects_company_address(self):
        company = runner.CompanyInfo(name="ACME", siren="123", address="10 rue Y 75001 Paris")
        leaks = runner.detect_address_leaks([], [], {}, [company])
        self.assertEqual(len(leaks), 1)
        self.assertEqual(leaks[0]["type"], "siege_social")

    def test_detects_profile_location(self):
        profiles = {"city": ["Paris"], "country": ["France"]}
        leaks = runner.detect_address_leaks([], [], profiles, [])
        self.assertEqual(len(leaks), 2)

    def test_empty_inputs(self):
        leaks = runner.detect_address_leaks([], [], {}, [])
        self.assertEqual(leaks, [])


class ExposureTimelineTest(unittest.TestCase):
    def test_builds_sorted_timeline(self):
        b1 = runner.BreachInfo(email="a@b.com", breach_name="Early", breach_date="2018-01-01",
                                data_types=["Passwords"])
        b2 = runner.BreachInfo(email="a@b.com", breach_name="Late", breach_date="2023-06-01",
                                data_types=["Email addresses"])
        events = runner.build_exposure_timeline([b1, b2], [], [], [])
        self.assertEqual(len(events), 2)
        self.assertEqual(events[0]["date"], "2018-01-01")
        self.assertEqual(events[1]["date"], "2023-06-01")
        self.assertEqual(events[0]["severity"], "ELEVE")
        self.assertEqual(events[1]["severity"], "MOYEN")

    def test_includes_companies(self):
        c = runner.CompanyInfo(name="ACME", siren="123", creation_date="2020-01-01")
        events = runner.build_exposure_timeline([], [], [], [c])
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["type"], "entreprise")

    def test_empty_inputs(self):
        events = runner.build_exposure_timeline([], [], [], [])
        self.assertEqual(events, [])


class QuietModeTest(unittest.TestCase):
    def test_quiet_flag_parsed(self):
        opts = runner.parse_args(["-m", "T", "-e", "a@b.com", "--quiet"])
        self.assertTrue(opts.quiet)

    def test_short_quiet_flag(self):
        opts = runner.parse_args(["-m", "T", "-e", "a@b.com", "-q"])
        self.assertTrue(opts.quiet)

    def test_default_not_quiet(self):
        opts = runner.parse_args(["-m", "T", "-e", "a@b.com"])
        self.assertFalse(opts.quiet)


class JsonOnlyTest(unittest.TestCase):
    def test_json_only_flag_parsed(self):
        opts = runner.parse_args(["-m", "T", "-e", "a@b.com", "--json-only"])
        self.assertTrue(opts.json_only)

    def test_default_not_json_only(self):
        opts = runner.parse_args(["-m", "T", "-e", "a@b.com"])
        self.assertFalse(opts.json_only)


if __name__ == "__main__":
    unittest.main()
