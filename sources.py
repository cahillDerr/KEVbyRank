#Downloadss the data KEVRank needs: CISA KEV, FIRST EPSS and NVD CVSS
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev():
    #Return {cve_id: kev_entry} for every CVE in CISA's catalog
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    catalog = response.json()
    return {entry["cveID"]: entry for entry in catalog["vulnerabilities"]}


EPSS_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH = 100  # the CVE IDs per EPSS request


def fetch_epss(cves):
    #returns {cve_id: probability} for every CVE that has an EPSS score
    scores = {}
    for start in range(0, len(cves), EPSS_BATCH):
        batch = cves[start:start + EPSS_BATCH]
        response = requests.get(EPSS_URL, params={"cve": ",".join(batch)}, timeout=30)
        response.raise_for_status()
        for row in response.json()["data"]:
            scores[row["cve"]] = float(row["epss"])  # rem the API sends nums as strings
    return scores