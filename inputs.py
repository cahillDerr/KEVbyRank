#this just reads the list of findings to rank from a pip-audit report or a plain txt file


def parse_cve_list(lines):
    # turns lines of text into findings and lines that are not CVE IDs are skipped
    findings = []
    for line in lines:
        cve = line.strip().upper()
        if cve.startswith("CVE-"):
            findings.append({"cve": cve, "package": "", "version": "", "fix": ""})
    return findings


def read_findings(path):
    #this Reads a text file with one CVE ID per line
    with open(path) as handle:
        return parse_cve_list(handle.readlines())