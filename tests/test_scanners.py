import threading

from app.scanners.nmap import parse_xml
from app.scanners.nuclei import parse_jsonl
from app.scanners.target import TargetError, normalize_target
from app.services.nvd import normalize as normalize_cve


def test_private_target_is_normalized():
    assert normalize_target("https://127.0.0.1/login") == "127.0.0.1"


def test_target_rejects_option_like_input():
    try:
        normalize_target("--script=vuln")
    except TargetError:
        pass
    else:
        raise AssertionError("option-like target should be rejected")


def test_nmap_xml_parser_extracts_web_service():
    output = """<?xml version="1.0"?><nmaprun><host><address addr="127.0.0.1" addrtype="ipv4"/><ports><port protocol="tcp" portid="8080"><state state="open"/><service name="http" product="Test Server" version="1.2"/></port></ports></host></nmaprun>"""
    services = parse_xml("127.0.0.1", output)
    assert services[0]["port"] == 8080
    assert services[0]["url"] == "http://127.0.0.1:8080"


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
