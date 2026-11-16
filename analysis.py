#Compare a CVSSonly patch policy with KEVRanks exploit awareness order
import argparse

import matplotlib
matplotlib.use("Agg")  # draws straight to a file so  no window needed
import matplotlib.pyplot as plt
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


def draw_chart(table, path):
    """Scatter plot: CVSS severity against EPSS probability, KEV entries marked."""
    points = table.dropna(subset=["cvss", "epss"])
    in_kev = points[points["in_kev"]]
    not_kev = points[~points["in_kev"]]

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.scatter(not_kev["cvss"], not_kev["epss"], s=40, color="#2a78d6", alpha=0.75,
               edgecolors="white", linewidths=0.8, label="Not in KEV")
    ax.scatter(in_kev["cvss"], in_kev["epss"], s=90, color="#eb6834", marker="D",
               edgecolors="white", linewidths=0.8, label="In CISA KEV")
    for _, row in in_kev.iterrows():
        ax.annotate(row["cve"], (row["cvss"], row["epss"]), xytext=(0, 9),
                    textcoords="offset points", ha="center", fontsize=8, color="#52514e")

    ax.axhline(0.10, color="#52514e", linewidth=1, linestyle="--")
    ax.axvline(7.0, color="#52514e", linewidth=1, linestyle="--")
    ax.text(0.15, 0.115, "EPSS 10% (KEVRank tier 2 line)", fontsize=8, color="#52514e")
    ax.text(7.0, 1.02, "CVSS 7.0 (High starts)", transform=ax.get_xaxis_transform(),
            ha="center", fontsize=8, color="#52514e")

    ax.set_yscale("log")
    ax.set_xlim(0, 10.3)
    ax.set_ylim(top=1.5)
    ax.set_xlabel("CVSS base score (severity if exploited)")
    ax.set_ylabel("EPSS (chance of exploitation in 30 days, log scale)")
    ax.set_title("High CVSS does not mean likely to be exploited", loc="left")
    ax.grid(True, color="#e6e5e1", linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.legend(loc="upper left", frameon=False)
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)

    
def main():
    parser = argparse.ArgumentParser(description="Compare CVSS-only order with KEVRank order.")
    parser.add_argument("ranked_csv", nargs="?", default="results/ranked.csv")
    parser.add_argument("--chart", default="results/cvss_vs_epss.png")
    parser.add_argument("--summary", default="results/summary.txt")
    args = parser.parse_args()

    table = pd.read_csv(args.ranked_csv)
    with open(args.summary, "w") as handle:
        for line in report_lines(summarize(table)):
            print(line)
            print(line, file=handle)
    draw_chart(table, args.chart)
    print(f"Saved {args.summary} and {args.chart}")


if __name__ == "__main__":
    main()