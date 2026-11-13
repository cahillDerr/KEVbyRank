#KEVRank: rank CVEs by real world exploitation instead of CVSS alone
import argparse
import os

import pandas as pd

from inputs import read_findings
from scoring import EPSS_threshold, TIER_LABELS, assign_tier, cvss_severity
from sources import fetch_cvss, fetch_epss, fetch_kev


def build_table(findings, kev, epss, cvss, epss_threshold=EPSS_threshold):
    #this will join each finding with its KEV, EPSS and CVSS data, then sort into patch order
    rows = []
    for finding in findings:
        cve = finding["cve"]
        in_kev = cve in kev
        epss_score = epss.get(cve)
        cvss_score = cvss.get(cve)
        tier = assign_tier(in_kev, epss_score, cvss_score, epss_threshold)
        rows.append({
            "cve": cve,
            "package": finding["package"],
            "version": finding["version"],
            "tier": tier,
            "tier_label": TIER_LABELS[tier],
            "in_kev": in_kev,
            "ransomware": in_kev and kev[cve].get("knownRansomwareCampaignUse") == "Known",
            "epss": epss_score,
            "cvss": cvss_score,
            "severity": cvss_severity(cvss_score),
            "fix": finding["fix"],
        })
    table = pd.DataFrame(rows)
    table = table.sort_values(
        ["tier", "epss", "cvss", "cve"],
        ascending=[True, False, False, True],
        na_position="last",
    )
    table.insert(0, "rank", range(1, len(table) + 1))
    return table


def main():
    parser = argparse.ArgumentParser(description="Rank CVEs by KEV, then EPSS, then CVSS.")
    parser.add_argument("input", help="pip-audit JSON report, or a text file with one CVE ID per line")
    parser.add_argument("-o", "--output", default="results/ranked.csv", help="where to write the ranked CSV")
    parser.add_argument("--epss-threshold", type=float, default=EPSS_threshold,
                        help="EPSS probability that counts as likely exploited (default 0.10)")
    parser.add_argument("--top", type=int, default=15, help="how many rows to print")
    args = parser.parse_args()

    findings = read_findings(args.input)
    if not findings:
        print(f"No CVE IDs found in {args.input}")
        return
    cves = sorted({finding["cve"] for finding in findings})
    print(f"{len(findings)} findings, {len(cves)} unique CVEs")

    print("Downloading the CISA KEV catalog...")
    kev = fetch_kev()
    print("Fetching EPSS scores from FIRST...")
    epss = fetch_epss(cves)
    print("Fetching CVSS scores from NVD (slow the first time, cached after)...")
    cvss = fetch_cvss(cves)

    table = build_table(findings, kev, epss, cvss, args.epss_threshold)
    os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
    table.to_csv(args.output, index=False)

    print()
    print(table.head(args.top)[["rank", "cve", "package", "tier_label", "epss", "cvss"]].to_string(index=False))
    print()
    for tier, label in TIER_LABELS.items():
        print(f"Tier {tier} ({label}): {(table['tier'] == tier).sum()}")
    print(f"Wrote {len(table)} rows to {args.output}")


if __name__ == "__main__":
    main()