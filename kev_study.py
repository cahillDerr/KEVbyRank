# The study part: how would CVSS only triage have treated every CVE known to be exploited?
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

from analysis import percent
from scoring import EPSS_threshold, cvss_severity
from sources import fetch_epss, fetch_kev, fetch_kev_cvss

SEVERITIES = ["Critical", "High", "Medium", "Low", "Unknown"]


def main():
    print("Downloading the CISA KEV catalog...")
    kev = fetch_kev()
    cves = sorted(kev)
    print(f"Fetching EPSS scores for {len(cves)} CVEs...")
    epss = fetch_epss(cves)
    print("Fetching CVSS scores from NVD (hasKev filter)...")
    cvss = fetch_kev_cvss()

    rows = []
    for cve in cves:
        entry = kev[cve]
        rows.append({
            "cve": cve,
            "vendor": entry["vendorProject"],
            "product": entry["product"],
            "date_added": entry["dateAdded"],
            "ransomware": entry.get("knownRansomwareCampaignUse") == "Known",
            "epss": epss.get(cve),
            "cvss": cvss.get(cve),
            "severity": cvss_severity(cvss.get(cve)),
        })
    table = pd.DataFrame(rows)
    os.makedirs("results", exist_ok=True)
    table.to_csv("results/kev_study.csv", index=False)

    total = len(table)
    counts = table["severity"].value_counts().reindex(SEVERITIES, fill_value=0)
    scored = total - counts["Unknown"]
    not_critical = counts["High"] + counts["Medium"] + counts["Low"]
    below_high = counts["Medium"] + counts["Low"]
    low_epss = int((table["epss"] < EPSS_threshold).sum())
    lines = [
        f"KEV entries: {total} ({scored} with a CVSS score in NVD)",
        f"Not CVSS Critical: {not_critical} of {scored} ({percent(not_critical, scored)})",
        f"Below CVSS High: {below_high} of {scored} ({percent(below_high, scored)})",
        f"EPSS under 10% today: {low_epss} of {total} ({percent(low_epss, total)})",
        f"Linked to ransomware campaigns: {int(table['ransomware'].sum())}",
    ]
    with open("results/kev_study_summary.txt", "w") as handle:
        for line in lines:
            print(line)
            print(line, file=handle)

    fig, ax = plt.subplots(figsize=(7, 4))
    bars = ax.bar(SEVERITIES, counts.values, color="#2a78d6", width=0.6)
    ax.bar_label(bars, padding=3, fontsize=9, color="#52514e")
    ax.set_ylabel("KEV entries")
    ax.set_title("CVSS severity of every known exploited CVE", loc="left")
    ax.grid(True, axis="y", color="#e6e5e1", linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    fig.tight_layout()
    fig.savefig("results/kev_severity.png", dpi=150)
    print("Saved results/kev_study.csv, results/kev_study_summary.txt, results/kev_severity.png")


if __name__ == "__main__":
    main()