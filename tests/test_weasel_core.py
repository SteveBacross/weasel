import pytest
from pathlib import Path
from weasel.parser.requirements import parse_requirements, resolve_all_dependencies
from weasel.scanner.cve_scanner import get_cve_for_package
from weasel.scanner.license_checker import get_licenses, simplify_license_info
from weasel.code_analysis.code_checker import run_bandit_scan
from weasel.report.report_generator import build_report_data


def test_parse_requirements(tmp_path):
    test_file = tmp_path / "requirements.txt"
    test_file.write_text("""
    requests==2.28.1
    flask>=2.1
    # Un commentaire
    """)
    parsed = parse_requirements(test_file)
    assert len(parsed) == 2
    assert parsed[0]['name'] == 'requests'
    assert '>=' in parsed[1]['specifier']


def test_resolve_dependencies(tmp_path):
    test_file = tmp_path / "requirements.txt"
    test_file.write_text("requests==2.28.1")
    resolved = resolve_all_dependencies(test_file)
    names = [pkg['name'] for pkg in resolved]
    assert 'requests' in names


def test_cve_scanner_offline_cache():
    # on suppose que requests 2.19.0 est vulnérable et déjà en cache local
    vulns = get_cve_for_package("requests", "2.19.0", offline=True)
    assert isinstance(vulns, list)


def test_license_checker():
    raw = get_licenses()
    structured = simplify_license_info(raw)
    assert isinstance(structured, list)
    assert all('license' in lic for lic in structured)


def test_bandit_analysis():
    issues = run_bandit_scan(".", severity_level="low")
    assert isinstance(issues, list)


def test_build_report():
    dependencies = [{"name": "requests", "version": "2.28.1"}]
    vulns = {"requests": [{"id": "CVE-XXXX", "summary": "test", "severity": "low", "cvss_score": 5.0, "references": []}]}
    licenses = [{"name": "requests", "license": "Apache", "permissivity": "permissive"}]
    bandit = [{"filename": "main.py", "line_number": 1, "test_id": "B101", "issue_text": "Use of assert"}]
    report = build_report_data(dependencies, vulns, licenses, bandit)
    assert "date" in report
    assert len(report["dependencies"]) == 1
    assert len(report["vulnerabilities"]) == 1
