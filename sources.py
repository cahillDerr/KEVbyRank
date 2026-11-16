#Downloadss the data KEVRank needs: CISA KEV, FIRST EPSS and NVD CVSS

import json
import os
import time

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


def parse_cvss(cve_record):
    #Pull one CVSS base score out of an NVD CVE record, or None if it has none"
    metrics = cve_record.get("metrics", {})
    for version in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(version, [])
        if not entries:
            continue
        primary = [entry for entry in entries if entry.get("type") == "Primary"]
        chosen = primary[0] if primary else entries[0]
        return chosen["cvssData"]["baseScore"]
    return None


NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVSS_CACHE = "cache/cvss.json"

# NVD allows 5 requests per 30 seconds without an API key and 50 with one.
NVD_API_KEY = os.environ.get("NVD_API_KEY")
NVD_DELAY = 0.7 if NVD_API_KEY else 6.5


def nvd_get(params):
    #Make one NVD request. If NVD is slow, silent or rate limiting, wait and retry
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    for attempt in range(5):
        try:
            response = requests.get(NVD_URL, params=params, headers=headers, timeout=60)
            if response.status_code not in (403, 429, 503):
                response.raise_for_status()
                return response.json()
            print("  NVD is rate limiting, waiting 30 seconds...")
        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError):
            print("  NVD did not answer in time, waiting 30 seconds...")
        time.sleep(30)
    raise RuntimeError("NVD gave no usable answer after 5 tries. Run the command again later.")


def load_cache():
    if os.path.exists(CVSS_CACHE):
        with open(CVSS_CACHE) as handle:
            return json.load(handle)
    return {}


def save_cache(cache):
    os.makedirs(os.path.dirname(CVSS_CACHE), exist_ok=True)
    with open(CVSS_CACHE, "w") as handle:
        json.dump(cache, handle, indent=1, sort_keys=True)


def fetch_cvss(cves):
    # this jwil returns {cve_id: cvss_score_or_None}. it will only ask NVD for CVEs not in the cache
    cache = load_cache()
    missing = [cve for cve in cves if cve not in cache]
    for number, cve in enumerate(missing, start=1):
        print(f"  NVD {number}/{len(missing)}: {cve}")
        found = nvd_get({"cveId": cve})["vulnerabilities"]
        cache[cve] = parse_cvss(found[0]["cve"]) if found else None
        save_cache(cache)
        time.sleep(NVD_DELAY)
    return {cve: cache[cve] for cve in cves}

def fetch_kev_cvss():
    # should return {cve_id: cvss_score_or_None} for every CVE that NVD marks as in KEV.

    #NVDs hasKev filter returns them all in pages of up to 2k, so this takes one or two requests instead of one request 
    # per CVE.
    
    scores = {}
    start = 0
    while True:
        page = nvd_get(f"hasKev&resultsPerPage=2000&startIndex={start}")
        for item in page["vulnerabilities"]:
            scores[item["cve"]["id"]] = parse_cvss(item["cve"])
        start += len(page["vulnerabilities"])
        if not page["vulnerabilities"] or start >= page["totalResults"]:
            break
        time.sleep(NVD_DELAY)
    return scores