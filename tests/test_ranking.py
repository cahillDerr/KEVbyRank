from kevrank import build_table


def finding(cve):
    return {"cve": cve, "package": "demo", "version": "1.0", "fix": ""}


def test_patch_order_is_kev_then_epss_then_cvss():
    findings = [finding("CVE-A"), finding("CVE-B"), finding("CVE-C"), finding("CVE-D")]
    kev = {"CVE-C": {"knownRansomwareCampaignUse": "Known"}}
    epss = {"CVE-A": 0.001, "CVE-B": 0.60, "CVE-C": 0.02, "CVE-D": 0.001}
    cvss = {"CVE-A": 9.8, "CVE-B": 6.1, "CVE-C": 5.5, "CVE-D": 4.0}

    table = build_table(findings, kev, epss, cvss)

    # C is in KEV, B has high EPSS, A is only Critical on paper, D is routine.
    assert list(table["cve"]) == ["CVE-C", "CVE-B", "CVE-A", "CVE-D"]
    assert list(table["tier"]) == [1, 2, 3, 4]
    assert list(table["rank"]) == [1, 2, 3, 4]
    assert bool(table.iloc[0]["ransomware"]) is True


def test_missing_scores_sort_last_within_a_tier():
    findings = [finding("CVE-A"), finding("CVE-B")]
    table = build_table(findings, kev={}, epss={"CVE-B": 0.01}, cvss={})
    assert list(table["cve"]) == ["CVE-B", "CVE-A"]