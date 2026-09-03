import json
import subprocess
import unittest
from unittest.mock import patch

from app.scanning.nmap import NmapScanner, parse_nmap_discovery, parse_nmap_xml
from app.scanning.nuclei import NucleiScanner, parse_nuclei_jsonl
from app.scanning.scope import (
    ReconAuthorizationError,
    ReconScopeError,
    authorize_target,
)
from app.scanning.tool_runner import (
    ScannerOutputError,
    ScannerToolError,
    ScannerToolTimeoutError,
    ScannerToolUnavailableError,
    run_scanner_tool,
)


NMAP_XML = """<?xml version="1.0"?>
<nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports>
  <port protocol="tcp" portid="22"><state state="open"/>
    <service name="ssh" product="OpenSSH" version="9.0"/></port>
  <port protocol="tcp" portid="80"><state state="closed"/></port>
</ports></host></nmaprun>"""

REAL_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<?xml-stylesheet href="file:///opt/homebrew/share/nmap/nmap.xsl" type="text/xsl"?>
<nmaprun scanner="nmap" xmloutputversion="1.05"><host>
<address addr="127.0.0.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="8090"><state state="open"/>
<service name="http" product="uvicorn" version="test"/></port>
</ports></host></nmaprun>"""


class ReconScopeTests(unittest.TestCase):
    def test_authorization_and_loopback_are_required(self):
        with self.assertRaises(ReconAuthorizationError):
            authorize_target("http://127.0.0.1:8090", authorized=False)
        with self.assertRaises(ReconScopeError):
            authorize_target("https://example.com", authorized=True)

    def test_exact_allowlist_accepts_non_loopback_origin(self):
        target = authorize_target(
            "https://lab.example.test",
            authorized=True,
            allowed_origins=["https://lab.example.test/"],
        )
        self.assertEqual(target.origin, "https://lab.example.test")

    def test_origin_rejects_credentials_and_paths(self):
        for target in ("http://user:pass@localhost", "http://localhost/path"):
            with self.subTest(target=target), self.assertRaises(ReconScopeError):
                authorize_target(target, authorized=True)


class NmapAdapterTests(unittest.TestCase):
    def test_real_nmap_prolog_and_xml_declaration_parse_successfully(self):
        discovery = parse_nmap_discovery(
            REAL_NMAP_XML,
            asset_id="asset-1",
        )
        self.assertEqual(discovery.ip_addresses, ("127.0.0.1",))
        self.assertEqual(len(discovery.services), 1)
        self.assertEqual(discovery.services[0].port, 8090)

    def test_parser_preserves_open_service_metadata(self):
        services = parse_nmap_xml(NMAP_XML, asset_id="asset-1")
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0].port, 22)
        self.assertEqual(services[0].product, "OpenSSH")
        self.assertEqual(services[0].source, "nmap")
        discovery = parse_nmap_discovery(NMAP_XML, asset_id="asset-1")
        self.assertEqual(discovery.ip_addresses, ("127.0.0.1",))

    def test_parser_rejects_malformed_or_unsafe_xml(self):
        unsafe_documents = (
            "not xml",
            "<!DOCTYPE x><nmaprun/>",
            '<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<nmaprun>&xxe;</nmaprun>",
            "<!ENTITY xxe 'unsafe'><nmaprun/>",
        )
        for output in unsafe_documents:
            with self.subTest(output=output), self.assertRaises(ScannerOutputError):
                parse_nmap_xml(output, asset_id="asset-1")

    def test_runner_uses_fixed_argument_array(self):
        calls = []

        def runner(arguments, **kwargs):
            calls.append((arguments, kwargs))
            return NMAP_XML

        target = authorize_target("http://127.0.0.1:8090", authorized=True)
        NmapScanner("/opt/tools/nmap", runner=runner).scan(
            target,
            asset_id="asset-1",
        )
        self.assertEqual(calls[0][0][0], "/opt/tools/nmap")
        self.assertEqual(calls[0][0][-1], "127.0.0.1")
        self.assertIn("-oX", calls[0][0])
        self.assertEqual(
            calls[0][0][calls[0][0].index("-p") + 1],
            "8090",
        )
        self.assertIn("-Pn", calls[0][0])
        self.assertEqual(calls[0][1]["scanner_name"], "nmap")


class NucleiAdapterTests(unittest.TestCase):
    def setUp(self):
        self.target = authorize_target(
            "http://127.0.0.1:8090",
            authorized=True,
        )

    def test_parser_preserves_explicit_candidate_context(self):
        output = json.dumps({
            "template-id": "synthetic-sqli",
            "matched-at": "http://127.0.0.1:8090/items?id=1",
            "matcher-name": "candidate",
            "info": {
                "name": "Synthetic SQLi candidate",
                "severity": "high",
                "reference": ["https://example.test/advisory"],
                "metadata": {
                    "obsidian-vulnerability-type": "sql_injection",
                    "obsidian-http-method": "GET",
                    "obsidian-parameter-name": "id",
                    "obsidian-parameter-location": "query",
                },
            },
            "timestamp": "2026-09-03T10:00:00Z",
        })
        candidate = parse_nuclei_jsonl(
            output,
            target=self.target,
            scan_id="scan-1",
            asset_id="asset-1",
        )[0]
        self.assertEqual(candidate.endpoint, "/items")
        self.assertEqual(candidate.parameter_name, "id")
        self.assertEqual(candidate.vulnerability_type, "sql_injection")
        self.assertEqual(candidate.scanner_template_id, "synthetic-sqli")
        self.assertEqual(
            candidate.evidence_refs,
            ["https://example.test/advisory"],
        )
        self.assertEqual(candidate.observed_at, "2026-09-03T10:00:00Z")

    def test_parser_does_not_guess_context_from_template_name(self):
        output = json.dumps({
            "template-id": "looks-like-sqli",
            "matched-at": "http://127.0.0.1:8090/items",
            "info": {"name": "SQL injection maybe", "severity": "high"},
        })
        candidate = parse_nuclei_jsonl(
            output,
            target=self.target,
            scan_id="scan-1",
            asset_id="asset-1",
        )[0]
        self.assertEqual(candidate.vulnerability_type, "nuclei_candidate")
        self.assertIsNone(candidate.parameter_name)

    def test_parser_rejects_cross_origin_and_malformed_records(self):
        outside = json.dumps({
            "template-id": "test",
            "matched-at": "http://example.com/path",
        })
        with self.assertRaises(ReconScopeError):
            parse_nuclei_jsonl(
                outside,
                target=self.target,
                scan_id="scan-1",
                asset_id="asset-1",
            )
        with self.assertRaises(ScannerOutputError):
            parse_nuclei_jsonl(
                "{bad-json",
                target=self.target,
                scan_id="scan-1",
                asset_id="asset-1",
            )

    def test_runner_uses_configured_binary_and_authorized_origin(self):
        calls = []

        def runner(arguments, **kwargs):
            calls.append((arguments, kwargs))
            return ""

        NucleiScanner("/opt/tools/nuclei", runner=runner).scan(
            self.target,
            scan_id="scan-1",
            asset_id="asset-1",
        )
        self.assertEqual(calls[0][0][0], "/opt/tools/nuclei")
        self.assertIn(self.target.origin, calls[0][0])
        self.assertEqual(
            calls[0][0][calls[0][0].index("-type") + 1],
            "http",
        )
        self.assertIn("-disable-redirects", calls[0][0])
        self.assertIn("-no-interactsh", calls[0][0])
        self.assertIn("-disable-update-check", calls[0][0])
        self.assertIn("-omit-raw", calls[0][0])
        self.assertEqual(
            calls[0][0][calls[0][0].index("-timeout") + 1],
            "3",
        )
        self.assertEqual(
            calls[0][0][calls[0][0].index("-rate-limit") + 1],
            "25",
        )
        self.assertEqual(calls[0][1]["scanner_name"], "nuclei")


class ScannerToolRunnerTests(unittest.TestCase):
    @patch("app.scanning.tool_runner.subprocess.run")
    def test_subprocess_has_no_shell_and_bounds_output(self, run):
        run.return_value = subprocess.CompletedProcess(["tool"], 0, "ok", "")
        self.assertEqual(
            run_scanner_tool(["tool", "--json"], timeout_seconds=1),
            "ok",
        )
        kwargs = run.call_args.kwargs
        self.assertNotIn("shell", kwargs)
        self.assertEqual(run.call_args.args[0], ["tool", "--json"])

    @patch("app.scanning.tool_runner.subprocess.run")
    def test_subprocess_failures_are_structured(self, run):
        run.side_effect = FileNotFoundError()
        with self.assertRaises(ScannerToolUnavailableError):
            run_scanner_tool(["missing"], timeout_seconds=1)
        run.side_effect = subprocess.TimeoutExpired(["tool"], 1)
        with self.assertRaises(ScannerToolTimeoutError):
            run_scanner_tool(["tool"], timeout_seconds=1)
        run.side_effect = None
        run.return_value = subprocess.CompletedProcess(["tool"], 2, "", "secret")
        with self.assertRaisesRegex(ScannerToolError, "stderr_bytes=6"):
            run_scanner_tool(["tool"], timeout_seconds=1)

    @patch("app.scanning.tool_runner.subprocess.run")
    def test_timeout_identifies_nmap_without_exposing_command(self, run):
        run.side_effect = subprocess.TimeoutExpired(["secret-command"], 30)
        target = authorize_target("http://127.0.0.1:8090", authorized=True)
        with self.assertRaisesRegex(
            ScannerToolTimeoutError,
            "^nmap scanner exceeded its configured timeout$",
        ):
            NmapScanner("/opt/tools/nmap").scan(target, asset_id="asset-1")

    @patch("app.scanning.tool_runner.subprocess.run")
    def test_timeout_identifies_nuclei_without_exposing_command(self, run):
        run.side_effect = subprocess.TimeoutExpired(["secret-command"], 60)
        target = authorize_target("http://127.0.0.1:8090", authorized=True)
        with self.assertRaisesRegex(
            ScannerToolTimeoutError,
            "^nuclei scanner exceeded its configured timeout$",
        ):
            NucleiScanner("/opt/tools/nuclei").scan(
                target,
                scan_id="scan-1",
                asset_id="asset-1",
            )


if __name__ == "__main__":
    unittest.main()
