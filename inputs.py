#this just reads the list of findings to rank from a pip-audit report or a plain txt file
import json

def parse_cve_list(lines):
    # turns lines of text into findings and lines that are not CVE IDs are skipped
    findings = []
    for line in lines:
        cve = line.strip().upper()
        if cve.startswith("CVE-"):
            findings.append({"cve": cve, "package": "", "version": "", "fix": ""})
    return findings

def parse_pip_audit(report):
    #Turn a loaded pipaudit JSON report into a list of findings.

    #One finding is one CVE in one package. pip-audit often lists the same CVE
    #twice (once under a PYSEC id, once under a GHSA id), so duplicates are dropped.

    findings = []
    seen = set()
    for dependency in report["dependencies"]:
        for vuln in dependency.get("vulns", []):
            ids = [vuln["id"]] + vuln.get("aliases", [])
            for cve in ids:
                if not cve.startswith("CVE-"):
                    continue
                key = (dependency["name"], cve)
                if key in seen:
                    continue
                seen.add(key)
                findings.append({
                    "cve": cve,
                    "package": dependency["name"],
                    "version": dependency.get("version", ""),
                    "fix": ", ".join(vuln.get("fix_versions", [])),
                })
    return findings


def read_findings(path):
    #picks the right parser from the file extension
    with open(path) as handle:
        if path.endswith(".json"):
            return parse_pip_audit(json.load(handle))
        return parse_cve_list(handle.readlines())