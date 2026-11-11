
import requests

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

# 1. CISA KEV: so one JSON file holding the whole catalog
kev = requests.get(KEV_URL, timeout=30).json()
print("KEV top level keys:", list(kev.keys()))
print("KEV entries:", kev["count"])
print("First entry:")
for key, value in kev["vulnerabilities"][0].items():
    print(f"  {key}: {str(value)[:70]}")

# 2. FIRST EPSS: ask for a few CVEs in one request, comma separated
cves = ["CVE-2021-44228", "CVE-2019-19844", "CVE-2018-18074"]
epss = requests.get(EPSS_URL, params={"cve": ",".join(cves)}, timeout=30).json()
print()
print("EPSS top level keys:", list(epss.keys()))
for row in epss["data"]:
    print(" ", row)
    print("   type of the epss value:", type(row["epss"]).__name__)