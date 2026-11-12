#Downloadss the data KEVRank needs: CISA KEV, FIRST EPSS and NVD CVSS
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev():
    #Return {cve_id: kev_entry} for every CVE in CISA's catalog
    response = requests.get(KEV_URL, timeout=30)
    response.raise_for_status()
    catalog = response.json()
    return {entry["cveID"]: entry for entry in catalog["vulnerabilities"]}