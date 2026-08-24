import threading

import pytest

from app.scanners.nmap import parse_live_hosts, parse_xml
from app.scanners.nse import parse_xml as parse_nse_xml
from app.scanners.nuclei import parse_jsonl
from app.scanners.target import TargetError, normalize_target
from app.scanners.ssh_audit import parse_output as parse_ssh_output
from app.scanners.trivy import TrivyParseError, parse_json as parse_trivy_json
from app.services.cve_match import has_concrete_version, normalize_cpe, severity_from_score
from app.services.nvd import normalize as normalize_cve


def test_private_target_is_normalized():
    assert normalize_target("https://127.0.0.1/login", authorization_confirmed=True) == "127.0.0.1"


def test_target_rejects_option_like_input():
    try:
        normalize_target("--script=vuln")
    except TargetError:
        pass
    else:
        raise AssertionError("option-like target should be rejected")


def test_nmap_xml_parser_extracts_web_service():
    output = """<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Test Server" version="1.2"><cpe>cpe:/a:test:server:1.2</cpe></service></port></ports></host></nmaprun>"""
    services = parse_xml("127.0.0.1", output)
    assert services[0]["port"] == 8080
    assert services[0]["url"] == "http://127.0.0.1:8080"
    assert services[0]["cpe"] == "cpe:/a:test:server:1.2"


def test_host_discovery_parser_keeps_only_live_ip_addresses():
    output = """<nmaprun><host><status state="up"/><address addr="192.168.1.10" addrtype="ipv4"/><address addr="00:11:22:33:44:55" addrtype="mac"/></host><host><status state="down"/><address addr="192.168.1.11" addrtype="ipv4"/></host></nmaprun>"""
    assert parse_live_hosts(output) == ["192.168.1.10"]


def test_nse_parser_reports_positive_and_skips_negative_results():
    output = """<nmaprun><host><address addr="192.168.1.10" addrtype="ipv4"/><ports><port protocol="tcp" portid="445"><script id="smb-vuln-test" output="VULNERABLE: CVE-2024-12345"/><script id="safe-test" output="The host does not appear to be vulnerable to CVE-2024-9999"/></port></ports></host></nmaprun>"""
    findings = parse_nse_xml("192.168.1.10", output)
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert findings[0]["cve_id"] == "CVE-2024-12345"


def test_cpe_normalization_and_cvss_severity():
    assert normalize_cpe("cpe:/a:nginx:nginx:1.24") == "cpe:2.3:a:nginx:nginx:1.24:*:*:*:*:*:*:*"
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.5) == "high"
    assert severity_from_score(5.0) == "medium"
    assert has_concrete_version("cpe:/a:nginx:nginx:1.24")
    assert not has_concrete_version("cpe:/a:nginx:nginx:*")


def test_trivy_parser_normalizes_vulnerabilities_and_misconfigurations():
    output = """{"Results":[{"Target":"requirements.txt","Vulnerabilities":[{"VulnerabilityID":"CVE-2025-1234","PkgName":"demo","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"HIGH"}],"Misconfigurations":[{"ID":"CFG-1","Title":"Unsafe setting","Severity":"MEDIUM","Message":"setting=true"}]}]}"""
    findings = parse_trivy_json(output, ".")
    assert len(findings) == 2
    assert findings[0]["cve_id"] == "CVE-2025-1234"
    assert findings[0]["severity"] == "high"
    assert findings[1]["source_tool"] == "trivy"


def test_trivy_parser_rejects_invalid_or_incompatible_output():
    with pytest.raises(TrivyParseError):
        parse_trivy_json("not-json", ".")
    with pytest.raises(TrivyParseError):
        parse_trivy_json("{}", ".")


def test_ssh_audit_parser_detects_configuration_and_updates():
    output = """__KMN_OS__
NAME=Debian
__KMN_SSH__
PermitRootLogin yes
PasswordAuthentication yes
__KMN_UPDATES__
Listing...
openssl/stable 3.0 amd64 [upgradable from: 2.9]
"""
    findings = parse_ssh_output("192.168.1.20", 22, output)
    severities = {item["severity"] for item in findings}
    assert "high" in severities
    assert "medium" in severities
    assert any(item["rule_id"] == "pending-updates" for item in findings)


def test_nuclei_parser_normalizes_finding():
    output = '{"template-id":"missing-header","host":"http://127.0.0.1","matched-at":"http://127.0.0.1","info":{"name":"Missing Header","severity":"medium","description":"Header is absent","classification":{"cwe-id":"CWE-693"}}}'
    findings = parse_jsonl(output, "http://127.0.0.1")
    assert findings[0]["title"] == "Missing Header"
    assert findings[0]["severity"] == "medium"
    assert findings[0]["cwe_id"] == "CWE-693"


def test_nvd_normalizer_keeps_reference_metadata():
    cve = normalize_cve({
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "en", "value": "Example issue"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1, "vectorString": "CVSS:3.1/AV:N"}}]},
        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}],
    })
    assert cve["id"] == "CVE-2024-0001"
    assert cve["cvss_score"] == 8.1
