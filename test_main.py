from main import deduplicate, is_public_host, recommend_version


def test_recommend_version_picks_highest_needed_fix():
    vulns = [
        {"cve": "CVE-1", "severity": "HIGH", "summary": "", "fixed_in": ["2.3.2", "2.2.5"]},
        {"cve": "CVE-2", "severity": "LOW", "summary": "", "fixed_in": ["3.1.3"]},
    ]
    assert recommend_version("2.0.1", vulns) == "3.1.3"


def test_recommend_version_returns_none_without_vulnerabilities():
    assert recommend_version("3.1.3", []) is None


def test_recommend_version_compares_versions_numerically():
    vulns = [{"cve": "CVE-1", "severity": "HIGH", "summary": "", "fixed_in": ["2.10.0"]}]
    assert recommend_version("2.9.0", vulns) == "2.10.0"


def test_deduplicate_keeps_one_entry_per_cve_and_prefers_known_severity():
    vulns = [
        {"id": "PYSEC-1", "aliases": ["CVE-2023-1"]},
        {"id": "GHSA-1", "aliases": ["CVE-2023-1"], "summary": "Real summary",
         "database_specific": {"severity": "HIGH"}},
    ]
    result = deduplicate(vulns)
    assert len(result) == 1
    assert result[0]["severity"] == "HIGH"


def test_deduplicate_sorts_by_severity():
    vulns = [
        {"id": "A", "aliases": ["CVE-LOW"], "database_specific": {"severity": "LOW"}},
        {"id": "B", "aliases": ["CVE-HIGH"], "database_specific": {"severity": "HIGH"}},
    ]
    result = deduplicate(vulns)
    assert [v["severity"] for v in result] == ["HIGH", "LOW"]



def test_is_public_host_blocks_internal_addresses():
    assert is_public_host("127.0.0.1") is False
    assert is_public_host("localhost") is False
    assert is_public_host("192.168.1.1") is False
    assert is_public_host("10.0.0.5") is False
    assert is_public_host("169.254.169.254") is False


def test_is_public_host_allows_public_ip():
    assert is_public_host("8.8.8.8") is True

