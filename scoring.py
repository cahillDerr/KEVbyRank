"""Tier rules for the kevrank. only functions"""

EPSS_threshold = 0.10  # there is a 10% estimated chance of exploitation in the next 30 days
CVSS_high = 7.0        # CVSS v3 "High" severity starts at 7.0

TIER_LABELS = {
    1: "Known exploited (KEV)",
    2: "Likely exploited (EPSS)",
    3: "Severe, exploitation unlikely",
    4: "Routine",
}


def assign_tier(in_kev, epss, cvss, epss_threshold=EPSS_threshold):
    #Return a tier from 1 (patch first) to 4 (patch last) for one CVE
    if in_kev:
        return 1
    if epss is not None and epss >= epss_threshold:
        return 2
    if cvss is not None and cvss >= CVSS_high:
        return 3
    return 4