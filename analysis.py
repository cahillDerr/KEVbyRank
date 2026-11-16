#Compare a CVSSonly patch policy with KEVRanks exploit awareness order
import argparse

import pandas as pd

LOW_EPSS = 0.01  # under a 1% estimated chance of exploitation in the next 30 days


def percent(part, whole):
    return f"{100 * part / whole:.0f}%" if whole else "n/a"


def summarize(table):
    #counts the things that differ between the two ways of ordering the queue
    critical = table[table["cvss"] >= 9.0]
    high_up = table[table["cvss"] >= 7.0]
    kev = table[table["in_kev"]]
    urgent = table[table["tier"] <= 2]  # KEV or likely exploited
    return {
        "findings": len(table),
        "critical": len(critical),
        "critical_low_epss": int((critical["epss"] < LOW_EPSS).sum()),
        "high_up": len(high_up),
        "high_up_low_epss": int((high_up["epss"] < LOW_EPSS).sum()),
        "kev": len(kev),
        "kev_not_critical": int((~(kev["cvss"] >= 9.0)).sum()),
        "urgent": len(urgent),
        "urgent_not_critical": int((~(urgent["cvss"] >= 9.0)).sum()),
        "urgent_below_high": int((~(urgent["cvss"] >= 7.0)).sum()),
    }


def report_lines(s):
    #turns the counts into sentences for the terminal and the README
    return [
        f"Findings analysed: {s['findings']}",
        f"CVSS Critical (9.0+): {s['critical']}. Of those, {s['critical_low_epss']} "
        f"({percent(s['critical_low_epss'], s['critical'])}) have EPSS under 1%.",
        f"CVSS High or Critical (7.0+): {s['high_up']}. Of those, {s['high_up_low_epss']} "
        f"({percent(s['high_up_low_epss'], s['high_up'])}) have EPSS under 1%.",
        f"In CISA KEV: {s['kev']} (not CVSS Critical: {s['kev_not_critical']}).",
        f"Urgent under KEVRank (tier 1 or 2): {s['urgent']}, against {s['high_up']} under a "
        f"'patch every High and Critical' policy.",
        f"Urgent findings that are not CVSS Critical: {s['urgent_not_critical']}. "
        f"Below CVSS High: {s['urgent_below_high']}.",
    ]


def main():
    parser = argparse.ArgumentParser(description="Compare CVSS-only order with KEVRank order.")
    parser.add_argument("ranked_csv", nargs="?", default="results/ranked.csv")
    parser.add_argument("--summary", default="results/summary.txt")
    args = parser.parse_args()

    table = pd.read_csv(args.ranked_csv)
    with open(args.summary, "w") as handle:
        for line in report_lines(summarize(table)):
            print(line)
            print(line, file=handle)
    print(f"Saved {args.summary}")


if __name__ == "__main__":
    main()