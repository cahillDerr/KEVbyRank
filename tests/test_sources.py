from sources import parse_cvss


def test_parse_cvss_prefers_v31_primary():
    record = {"metrics": {
        "cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 5.0}}],
        "cvssMetricV31": [
            {"type": "Secondary", "cvssData": {"baseScore": 8.1}},
            {"type": "Primary", "cvssData": {"baseScore": 9.8}},
        ],
    }}
    assert parse_cvss(record) == 9.8


def test_parse_cvss_falls_back_to_v2():
    record = {"metrics": {"cvssMetricV2": [{"type": "Primary", "cvssData": {"baseScore": 6.9}}]}}
    assert parse_cvss(record) == 6.9


def test_parse_cvss_handles_records_with_no_score():
    assert parse_cvss({"metrics": {}}) is None
    assert parse_cvss({}) is None