from inputs import parse_cve_list, parse_pip_audit

REPORT = {
    "dependencies": [
        {
            "name": "django",
            "version": "2.1.5",
            "vulns": [
                {"id": "PYSEC-2019-13", "fix_versions": ["2.1.11", "2.2.4"],
                 "aliases": ["CVE-2019-14234", "GHSA-6r97-cj55-9hrq"]},
                # same CVE again under its GHSA id: must not be counted twice
                {"id": "GHSA-6r97-cj55-9hrq", "fix_versions": ["2.1.11"],
                 "aliases": ["CVE-2019-14234"]},
                # no CVE alias at all: skipped
                {"id": "PYSEC-2020-999", "fix_versions": [], "aliases": []},
            ],
        },
        {"name": "requests", "version": "2.21.0", "vulns": []},
        {"name": "broken-package", "skip_reason": "could not be audited"},
    ]
}


def test_pip_audit_keeps_one_row_per_package_and_cve():
    findings = parse_pip_audit(REPORT)
    assert len(findings) == 1
    assert findings[0] == {
        "cve": "CVE-2019-14234",
        "package": "django",
        "version": "2.1.5",
        "fix": "2.1.11, 2.2.4",
    }


def test_cve_list_skips_blanks_and_comments():
    lines = ["# my scan", "", "cve-2021-44228", "  CVE-2019-19844  ", "not a cve"]
    findings = parse_cve_list(lines)
    assert [finding["cve"] for finding in findings] == ["CVE-2021-44228", "CVE-2019-19844"]